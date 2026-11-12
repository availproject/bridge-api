use crate::error::{ErrorResponse, UpstreamError};
use crate::heads::{ChainHeadResponse, HeaderBlockNumber, get_head};
use crate::state::AppState;
#[cfg(test)]
use crate::state::test_state;

use alloy::primitives::{B256, U256};
use anyhow::{Result, anyhow};
use avail_core::data_proof::AddressedMessage;
#[cfg(test)]
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
#[cfg(test)]
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::{
    core::ClientError, core::client::ClientT, http_client::transport::Error as TransportError,
    rpc_params,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tokio::join;
use tokio::task::JoinHandle;
use tracing::warn;

#[inline(always)]
pub(crate) async fn get_eth_proof(
    Path(block_hash): Path<B256>,
    Query(index_struct): Query<IndexStruct>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let cloned_state = state.clone();
    let data_proof_response_fut = tokio::spawn(async move {
        cloned_state
            .avail_client
            .request(
                "kate_queryDataProof",
                rpc_params![index_struct.index, &block_hash],
            )
            .await
    });

    let eth_proof_cache_maxage = state.eth_proof_cache_maxage;
    let eth_proof_failure_cache_maxage = state.eth_proof_failure_cache_maxage;
    let url = format!(
        "{}?chainName={}&contractChainId={}&contractAddress={}&blockHash={}",
        state.merkle_proof_service_base_url,
        state.avail_chain_name,
        state.contract_chain_id,
        state.contract_address,
        block_hash
    );

    let mekrle_proof_response_fut = tokio::spawn(async move {
        let merkle_proof_response = state.request_client.get(url).send().await;
        match merkle_proof_response {
            Ok(resp) => resp.json::<MekrleProofAPIResponse>().await,
            Err(err) => Err(err),
        }
    });
    let (data_proof, merkle_proof_response) =
        join!(data_proof_response_fut, mekrle_proof_response_fut);
    let data_proof_res: KateQueryDataProofResponse = data_proof
        .map_err(|e| {
            tracing::error!("❌ Failed to fetch the kate query data. Error: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow::anyhow!("Something went wrong."),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?
        .map_err(|e| {
            tracing::error!("❌ Failed to get the kate query data. Error: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow::anyhow!("Failed to get the kate query data."),
                StatusCode::BAD_REQUEST,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

    let merkle_proof_data = merkle_proof_response
        .map_err(|e| {
            tracing::error!("❌ Failed to get the merkle proof data. Error: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow::anyhow!("Failed to get the merkle proof data."),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?
        .map_err(|_| {
            let e = UpstreamError::MerkleProofService;
            tracing::error!("❌ Merkle proof api response was unsuccessful. Error: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow::anyhow!("Something went wrong."),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;
    let merkle_data = match merkle_proof_data {
        MekrleProofAPIResponse {
            data: Some(data), ..
        } => data,
        MekrleProofAPIResponse {
            success: Some(false),
            error: Some(data),
            ..
        } => {
            if data.contains("not in the range of blocks") {
                warn!(
                    "⏳ Merkle proof VectorX contract not updated yet! Response: {}",
                    data
                );

                return Err(ErrorResponse::with_status_and_headers(
                    anyhow!("VectorX contract not updated yet!"),
                    StatusCode::NOT_FOUND,
                    &[(
                        "Cache-Control",
                        &format!(
                            "public, max-age={eth_proof_failure_cache_maxage}, must-revalidate"
                        ),
                    )],
                ));
            } else {
                tracing::error!("❌ Merkle API returned unsuccessfully. Response: {}", data);

                return Err(ErrorResponse::with_status_and_headers(
                    anyhow::anyhow!("Something went wrong."),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &[("Cache-Control", "public, max-age=60, must-revalidate")],
                ));
            }
        }

        _ => {
            tracing::error!("❌ Merkle proof API returned no data");
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("Merkle proof API returned no data"),
                StatusCode::NOT_FOUND,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            ));
        }
    };

    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!("public, max-age={}, immutable", eth_proof_cache_maxage),
        )],
        Json(json!(AggregatedResponse {
            data_root_proof: merkle_data.merkle_branch,
            leaf_proof: data_proof_res.data_proof.proof,
            range_hash: merkle_data.range_hash,
            data_root_index: merkle_data.index,
            leaf: data_proof_res.data_proof.leaf,
            leaf_index: data_proof_res.data_proof.leaf_index,
            data_root: data_proof_res.data_proof.roots.data_root,
            blob_root: data_proof_res.data_proof.roots.blob_root,
            bridge_root: data_proof_res.data_proof.roots.bridge_root,
            data_root_commitment: merkle_data.data_commitment,
            block_hash,
            message: data_proof_res.message
        })),
    )
        .into_response())
}

/// True when the RPC server answered with HTTP 429.
fn is_rate_limited(e: &ClientError) -> bool {
    let ClientError::Transport(err) = e else {
        return false;
    };
    matches!(
        err.downcast_ref::<TransportError>(),
        Some(TransportError::Rejected { status_code: 429 })
    )
}

#[inline(always)]
pub(crate) async fn get_avl_proof(
    Path((block_hash, message_id_query)): Path<(B256, U256)>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let mut hasher = Keccak256::new();
    hasher.update(
        [
            message_id_query.to_be_bytes_vec(),
            U256::from(1).to_be_bytes_vec(),
        ]
        .concat(),
    );
    let result = hasher.finalize();
    let proof: Result<AccountStorageProofResponse, ClientError> = state
        .ethereum_client
        .request(
            "eth_getProof",
            rpc_params![
                state.bridge_contract_address.as_str(),
                [B256::from_slice(&result[..]).to_string()],
                block_hash
            ],
        )
        .await;
    let resp = proof.map_err(|e| {
        tracing::error!("❌ Cannot get account and storage proofs: {e:#}");
        if is_rate_limited(&e) {
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::TOO_MANY_REQUESTS,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        } else {
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        }
    })?;
    // eth_getProof can answer without a storage proof.
    let Some(storage_proof) = resp.storage_proof.into_iter().next() else {
        tracing::error!("❌ Cannot get account and storage proofs: empty storage proof");
        return Err(ErrorResponse::with_status_and_headers(
            anyhow!("Empty storage proof"),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "public, max-age=60, must-revalidate")],
        ));
    };

    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!(
                "public, max-age={}, immutable",
                state.avl_proof_cache_maxage
            ),
        )],
        Json(json!(EthProofResponse {
            account_proof: resp.account_proof,
            storage_proof: storage_proof.proof,
        })),
    )
        .into_response())
}

/// get_proof returns a proof from Avail for the provided chain id
#[inline(always)]
pub(crate) async fn get_proof(
    Path(chain_id): Path<u64>,
    Query(query_proof): Query<ProofQueryStruct>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let block_hash = query_proof.block_hash;
    let index = query_proof.index;

    let requested_block: HeaderBlockNumber = state
        .avail_client
        .request("chain_getHeader", rpc_params![block_hash])
        .await
        .map_err(|e| {
            ErrorResponse::with_status(
                anyhow!("Error fetching Avail block. {e:#}"),
                StatusCode::NOT_FOUND,
            )
        })?;
    {
        let head = fetch_chain_head(state.clone(), chain_id)
            .await
            .map_err(|e| {
                ErrorResponse::with_status_and_headers(
                    anyhow!("Cannot get chain head. {e:#}"),
                    StatusCode::NOT_FOUND,
                    &[("Cache-Control", "public, max-age=60, immutable")],
                )
            })?;
        {
            if requested_block.number > head {
                tracing::warn!(
                    "Contract not yet synced for the provided block hash {}, the last synced block number {}",
                    block_hash,
                    head
                );

                return Err(ErrorResponse::with_status_and_headers(
                    anyhow!(
                        "Provided block hash {:?} is not yet in the range.",
                        block_hash
                    ),
                    StatusCode::NOT_FOUND,
                    &[("Cache-Control", "public, max-age=60, immutable")],
                ));
            }
        }
    }

    let data_proof_response_fut = spawn_kate_proof(state.clone(), index, block_hash);
    let merkle_proof_range_fut = spawn_merkle_proof_range_fetch(state.clone(), block_hash);
    let (data_proof, range_response) = join!(data_proof_response_fut, merkle_proof_range_fut);

    let data_proof_res = data_proof
        .map_err(|e| {
            ErrorResponse::with_status_and_headers(
                anyhow!("error: {e:#}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "max-age=60, must-revalidate")],
            )
        })?
        .map_err(|e| {
            let err_str = e.to_string();
            let is_warn = err_str.contains("Missing block")
                || err_str.contains("Cannot fetch tx data")
                || err_str.contains("is not finalized");
            if is_warn {
                tracing::warn!("Cannot get kate data proof response: {:?}", e);
            } else {
                tracing::error!("Cannot get kate data proof response: {:?}", e);
            }
            ErrorResponse::with_status_and_headers(
                anyhow!("error: {e:#}"),
                StatusCode::BAD_REQUEST,
                &[("Cache-Control", "max-age=60, must-revalidate")],
            )
        })?;

    let range_data = match range_response.map_err(|e| {
        tracing::error!("Cannot get merkle proof response {:?}", e);
        ErrorResponse::with_status_and_headers(
            anyhow!("error: {e:#}"),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "max-age=60, must-revalidate")],
        )
    })? {
        Ok(MekrleProofAPIResponse {
            data: Some(data), ..
        }) => data,
        Ok(MekrleProofAPIResponse {
            success: Some(false),
            error: Some(data),
            ..
        }) => {
            if data.contains("not in the range of blocks") {
                warn!("VectorX contract not updated yet! Response: {}", data);
            } else {
                tracing::error!(
                    "Merkle proof API returned unsuccessfully. Response: {}",
                    data
                );
            }
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("error: {data}"),
                StatusCode::NOT_FOUND,
                &[("Cache-Control", "public, max-age=60, immutable")],
            ));
        }
        Err(_) => {
            let err = UpstreamError::MerkleProofService;
            tracing::error!("Cannot get merkle proof api response {:?}", err);
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("error: {err}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "max-age=60, must-revalidate")],
            ));
        }
        _ => {
            tracing::error!("Merkle proof API returned no data");
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("Merkle proof API returned no data"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "max-age=60, must-revalidate")],
            ));
        }
    };

    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!("public, max-age={}, immutable", state.proof_cache_maxage),
        )],
        Json(json!(AggregatedResponse::new(
            range_data,
            data_proof_res,
            block_hash
        ))),
    )
        .into_response())
}

// spawn_kate_proof fetch queryDataProof from Avail chain
fn spawn_kate_proof(
    state: Arc<AppState>,
    index: u32,
    block_hash: B256,
) -> JoinHandle<Result<KateQueryDataProofResponse, ClientError>> {
    tokio::spawn(async move {
        state
            .avail_client
            .request("kate_queryDataProof", rpc_params![index, &block_hash])
            .await
    })
}

// spawn_merkle_proof_range_fetch fetches merkle proof for a block range
fn spawn_merkle_proof_range_fetch(
    state: Arc<AppState>,
    block_hash: B256,
) -> JoinHandle<Result<MekrleProofAPIResponse, reqwest::Error>> {
    let url = format!(
        "{}?chainName={}&contractChainId={}&contractAddress={}&blockHash={}",
        state.merkle_proof_service_base_url,
        state.avail_chain_name,
        state.contract_chain_id,
        state.contract_address,
        block_hash
    );
    tokio::spawn(async move {
        let res = state.request_client.get(url).send().await;
        match res {
            Ok(resp) => resp.json::<MekrleProofAPIResponse>().await,
            Err(e) => Err(e),
        }
    })
}

// fetch_chain_head returns current state of the chain head on the chain with provided chain id
async fn fetch_chain_head(state: Arc<AppState>, chain_id: u64) -> Result<u32> {
    let response: Response<Body> = get_head(Path(chain_id), State(state)).await.into_response();
    if response.status() != StatusCode::OK {
        Err(anyhow::anyhow!(
            "Cannot fetch chain head for chain {}",
            chain_id
        ))
    } else {
        let body = response.into_body();
        let b = to_bytes(body, 2048).await?;
        let body: ChainHeadResponse = serde_json::from_slice(b.to_vec().as_slice())?;
        Ok(body.head)
    }
}

#[derive(Deserialize)]
pub struct IndexStruct {
    pub index: u32,
}

#[derive(Deserialize)]
pub struct ProofQueryStruct {
    pub index: u32,
    pub block_hash: B256,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KateQueryDataProofResponse {
    pub data_proof: DataProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<AddressedMessage>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataProof {
    pub roots: Roots,
    pub proof: Vec<B256>,
    pub leaf_index: u32,
    pub leaf: B256,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Roots {
    pub data_root: B256,
    pub blob_root: B256,
    pub bridge_root: B256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStorageProofResponse {
    pub account_proof: Vec<String>,
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize)]
pub struct StorageProof {
    pub proof: Vec<String>,
}

#[derive(Deserialize)]
pub struct MekrleProofAPIResponse {
    pub data: Option<MerkleProofData>,
    pub error: Option<String>,
    pub success: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProofData {
    pub range_hash: B256,
    pub data_commitment: B256,
    pub merkle_branch: Vec<B256>,
    pub index: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedResponse {
    pub data_root_proof: Vec<B256>,
    pub leaf_proof: Vec<B256>,
    pub range_hash: B256,
    pub data_root_index: u16,
    pub leaf: B256,
    pub leaf_index: u32,
    pub data_root: B256,
    pub blob_root: B256,
    pub bridge_root: B256,
    pub data_root_commitment: B256,
    pub block_hash: B256,
    pub message: Option<AddressedMessage>,
}

impl AggregatedResponse {
    pub fn new(
        range_data: MerkleProofData,
        data_proof_res: KateQueryDataProofResponse,
        hash: B256,
    ) -> Self {
        AggregatedResponse {
            data_root_proof: range_data.merkle_branch,
            leaf_proof: data_proof_res.data_proof.proof,
            range_hash: range_data.range_hash,
            data_root_index: range_data.index,
            leaf: data_proof_res.data_proof.leaf,
            leaf_index: data_proof_res.data_proof.leaf_index,
            data_root: data_proof_res.data_proof.roots.data_root,
            blob_root: data_proof_res.data_proof.roots.blob_root,
            bridge_root: data_proof_res.data_proof.roots.bridge_root,
            data_root_commitment: range_data.data_commitment,
            block_hash: hash,
            message: data_proof_res.message,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthProofResponse {
    pub account_proof: Vec<String>,
    pub storage_proof: Vec<String>,
}

#[tokio::test]
async fn test_avl_proof_rate_limited_when_rpc_answers_429() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", listener.local_addr().unwrap());
    let rpc = Router::new().fallback(|| async { StatusCode::TOO_MANY_REQUESTS });
    tokio::spawn(async move { axum::serve(listener, rpc).await });

    let mut state = Arc::into_inner(test_state()).unwrap();
    state.ethereum_client = HttpClientBuilder::default().build(rpc_url).unwrap();
    let response = get_avl_proof(Path((B256::ZERO, U256::from(1))), State(Arc::new(state)))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}
