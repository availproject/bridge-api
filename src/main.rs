use alloy_primitives::{hex, Address, B256, U256};
use avail_core::data_proof::AddressedMessage;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use chrono::Utc;
use http::Method;
use jsonrpsee::core::Error;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::Decode;
use sp_io::hashing::twox_128;
use std::env;
use std::sync::Arc;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tokio::join;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::prelude::*;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Debug)]
struct AppState {
    avail_client: HttpClient,
    ethereum_client: HttpClient,
    request_client: Client,
    succinct_base_url: String,
    beaconchain_base_url: String,
    indexer_base_url: String,
    avail_chain_name: String,
    contract_chain_id: String,
    contract_address: String,
    bridge_contract_address: String,
    eth_head_cache_maxage: u16,
    avl_head_cache_maxage: u16,
    avl_proof_cache_maxage: u32,
    eth_proof_cache_maxage: u32,
    slot_mapping_cache_maxage: u32,
    transactions_cache_maxage: u32,
}

#[derive(Deserialize)]
struct IndexStruct {
    index: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct KateQueryDataProofResponse {
    data_proof: DataProof,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    message: Option<AddressedMessage>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DataProof {
    roots: Roots,
    proof: Vec<B256>,
    leaf_index: u32,
    leaf: B256,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Roots {
    data_root: B256,
    blob_root: B256,
    bridge_root: B256,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountStorageProofResponse {
    account_proof: Vec<String>,
    storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize)]
struct StorageProof {
    proof: Vec<String>,
}

#[derive(Deserialize)]
struct SuccinctAPIResponse {
    data: Option<SuccinctAPIData>,
    error: Option<String>,
    success: Option<bool>,
}

#[derive(Deserialize)]
struct BeaconAPIResponse {
    status: String,
    data: BeaconAPIResponseData,
}

#[derive(Deserialize, Serialize)]
struct BeaconAPIResponseData {
    blockroot: B256,
    exec_block_number: u32,
    epoch: u32,
    slot: u32,
    exec_state_root: B256,
    exec_block_hash: B256,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SlotMappingResponse {
    block_hash: B256,
    block_number: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuccinctAPIData {
    range_hash: B256,
    data_commitment: B256,
    merkle_branch: Vec<B256>,
    index: u16,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregatedResponse {
    data_root_proof: Vec<B256>,
    leaf_proof: Vec<B256>,
    range_hash: B256,
    data_root_index: u16,
    leaf: B256,
    leaf_index: u32,
    data_root: B256,
    blob_root: B256,
    bridge_root: B256,
    data_root_commitment: B256,
    block_hash: B256,
    message: Option<AddressedMessage>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EthProofResponse {
    account_proof: Vec<String>,
    storage_proof: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeadResponse {
    pub slot: u64,
    pub timestamp: u64,
    pub timestamp_diff: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeBlocks {
    start: u32,
    end: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RangeBlocksAPIResponse {
    data: RangeBlocks,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Transaction {
    source_chain: Chain,
    destination_chain: Chain,
    message_id: u64,
    status: Status,
    source_transaction_hash: Option<String>,
    source_transaction_block_number: Option<u64>,
    source_transaction_index: Option<u32>,
    source_transaction_timestamp: Option<String>,
    destination_transaction_hash: Option<String>,
    destination_transaction_block_number: Option<u64>,
    destination_transaction_timestamp: Option<String>,
    destination_transaction_index: Option<u32>,
    destination_token_address: Option<String>,
    depositor_address: String,
    receiver_address: String,
    amount: Option<String>,
    data_type: String,
    block_hash: Option<String>,
    source_token_address: Option<String>,
    message: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PaginationData {
    has_next_page: bool,
    page: u32,
    page_size: u32,
    total_count: u32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Response {
    result: Option<Vec<Transaction>>,
    pagination_data: Option<PaginationData>,
}

#[derive(Serialize, Deserialize, Debug)]
enum Chain {
    #[serde(rename = "AVAIL")]
    Avail,
    #[serde(rename = "ETHEREUM")]
    Ethereum,
}

#[derive(Serialize, Deserialize, Debug)]
enum Status {
    #[serde(rename = "BRIDGED")]
    Bridged,
    #[serde(rename = "READY_TO_CLAIM")]
    ReadyToClaim,
    #[serde(rename = "CLAIMED")]
    Claimed,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TransactionQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    source_chain: Option<Chain>,
    destination_chain: Option<Chain>,
    status: Option<Status>,
    eth_address: Option<String>,
    avail_address: Option<String>,
}

async fn alive() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({ "name": "Avail Bridge API" })))
}

#[inline(always)]
async fn info(State(state): State<Arc<AppState>>) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "vectorXContractAddress": state.contract_address,
        "vectorXChainId": state.contract_chain_id,
        "bridgeContractAddress" : state.bridge_contract_address,
        "availChainName": state.avail_chain_name,
    })))
}

#[inline(always)]
async fn get_eth_proof(
    Path(block_hash): Path<B256>,
    Query(index_struct): Query<IndexStruct>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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
    let url = format!(
        "{}?chainName={}&contractChainId={}&contractAddress={}&blockHash={}",
        state.succinct_base_url,
        state.avail_chain_name,
        state.contract_chain_id,
        state.contract_address,
        block_hash
    );

    let succinct_response_fut = tokio::spawn(async move {
        let succinct_response = state.request_client.get(url).send().await;
        match succinct_response {
            Ok(resp) => resp.json::<SuccinctAPIResponse>().await,
            Err(err) => Err(err),
        }
    });
    let (data_proof, succinct_response) = join!(data_proof_response_fut, succinct_response_fut);
    let data_proof_res: KateQueryDataProofResponse = match data_proof {
        Ok(resp) => match resp {
            Ok(data) => data,
            Err(err) => {
                tracing::error!("❌ Cannot get kate data proof response: {:?}", err);
                return (
                    StatusCode::BAD_REQUEST,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": err.to_string()})),
                );
            }
        },
        Err(err) => {
            tracing::error!("❌ {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": err.to_string()})),
            );
        }
    };
    let succinct_data = match succinct_response {
        Ok(data) => match data {
            Ok(SuccinctAPIResponse {
                data: Some(data), ..
            }) => data,
            Ok(SuccinctAPIResponse {
                success: Some(false),
                error: Some(data),
                ..
            }) => {
                tracing::error!("❌ Succinct API returned unsuccessfully");
                return (
                    StatusCode::NOT_FOUND,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": data })),
                );
            }
            Err(err) => {
                tracing::error!("❌ {:?}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": err.to_string()})),
                );
            }
            _ => {
                tracing::error!("❌ Succinct API returned no data");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": "Succinct API returned no data"})),
                );
            }
        },
        Err(err) => {
            tracing::error!("❌ {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": err.to_string()})),
            );
        }
    };

    (
        StatusCode::OK,
        [(
            "Cache-Control",
            format!("public, max-age={}, immutable", eth_proof_cache_maxage),
        )],
        Json(json!(AggregatedResponse {
            data_root_proof: succinct_data.merkle_branch,
            leaf_proof: data_proof_res.data_proof.proof,
            range_hash: succinct_data.range_hash,
            data_root_index: succinct_data.index,
            leaf: data_proof_res.data_proof.leaf,
            leaf_index: data_proof_res.data_proof.leaf_index,
            data_root: data_proof_res.data_proof.roots.data_root,
            blob_root: data_proof_res.data_proof.roots.blob_root,
            bridge_root: data_proof_res.data_proof.roots.bridge_root,
            data_root_commitment: succinct_data.data_commitment,
            block_hash,
            message: data_proof_res.message
        })),
    )
}

#[inline(always)]
async fn get_avl_proof(
    Path((block_hash, message_id)): Path<(B256, U256)>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut hasher = Keccak256::new();
    hasher.update(
        [
            message_id.to_be_bytes_vec(),
            U256::from(1).to_be_bytes_vec(),
        ]
        .concat(),
    );
    let result = hasher.finalize();
    let proof: Result<AccountStorageProofResponse, jsonrpsee::core::Error> = state
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

    match proof {
        Ok(mut resp) => (
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
                storage_proof: resp.storage_proof.swap_remove(0).proof,
            })),
        ),
        Err(err) => {
            tracing::error!("❌ Cannot get account and storage proofs: {:?}", err);
            if err.to_string().ends_with("status code: 429") {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": err.to_string()})),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": err.to_string()})),
                )
            }
        }
    }
}

/// Creates a request to the beaconcha service for mapping slot to the block number.
#[inline(always)]
async fn get_beacon_slot(
    Path(slot): Path<U256>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let resp = state
        .request_client
        .get(format!("{}/{}", state.beaconchain_base_url, slot))
        .send()
        .await;

    match resp {
        Ok(ok) => {
            let response_data = ok.json::<BeaconAPIResponse>().await;
            match response_data {
                Ok(rsp_data) => {
                    if rsp_data.status == "OK" {
                        (
                            StatusCode::OK,
                            [(
                                "Cache-Control",
                                format!(
                                    "public, max-age={}, immutable",
                                    state.slot_mapping_cache_maxage
                                ),
                            )],
                            Json(json!(SlotMappingResponse {
                                block_number: rsp_data.data.exec_block_number,
                                block_hash: rsp_data.data.exec_block_hash
                            })),
                        )
                    } else {
                        tracing::error!(
                            "❌ Beacon API returned unsuccessfully: {:?}",
                            rsp_data.status
                        );
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                            Json(json!({ "error": "Cannot fetch slot data"})),
                        )
                    }
                }
                Err(err) => {
                    tracing::error!("❌ Cannot get beacon API response data: {:?}", err);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                        Json(json!({ "error": err.to_string()})),
                    )
                }
            }
        }
        Err(err) => {
            tracing::error!("❌ Cannot get beacon API data: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": err.to_string()})),
            )
        }
    }
}

/// get_eth_head returns Ethereum head with the latest slot/block that is stored and a time.
#[inline(always)]
async fn get_eth_head(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pallet = "Vector";
    let head = "Head";
    let timestamp = "Timestamps";

    let head_key = format!(
        "0x{}{}",
        hex::encode(twox_128(pallet.as_bytes())),
        hex::encode(twox_128(head.as_bytes()))
    );

    let finalized_block_hash_response: Result<String, Error> = state
        .avail_client
        .request("chain_getFinalizedHead", rpc_params![])
        .await;

    match finalized_block_hash_response {
        Ok(finalized_block_hash) => {
            let head_response: Result<String, Error> = state
                .avail_client
                .request(
                    "state_getStorage",
                    rpc_params![head_key, finalized_block_hash.clone()],
                )
                .await;
            match head_response {
                Ok(slot_storage_response) => {
                    let timestamp_key = format!(
                        "0x{}{}{}",
                        hex::encode(twox_128(pallet.as_bytes())),
                        hex::encode(twox_128(timestamp.as_bytes())),
                        &slot_storage_response[2..].to_string()
                    );
                    let timestamp_response: Result<String, Error> = state
                        .avail_client
                        .request(
                            "state_getStorage",
                            rpc_params![timestamp_key, finalized_block_hash.clone()],
                        )
                        .await;
                    match timestamp_response {
                        Ok(timestamp_storage_response) => {
                            // decode response from storage into readable values
                            let slot_from_hex =
                                sp_core::bytes::from_hex(slot_storage_response.as_str()).unwrap();
                            let slot_input = &mut slot_from_hex.as_slice();
                            let slot: u64 = Decode::decode(slot_input).unwrap();
                            let timestamp_from_hex =
                                sp_core::bytes::from_hex(timestamp_storage_response.as_str())
                                    .unwrap();
                            let timestamp_input = &mut timestamp_from_hex.as_slice();
                            let timestamp: u64 = Decode::decode(timestamp_input).unwrap();
                            let now = Utc::now().timestamp() as u64;
                            (
                                StatusCode::OK,
                                [(
                                    "Cache-Control",
                                    format!(
                                        "public, max-age={}, must-revalidate",
                                        state.eth_head_cache_maxage
                                    ),
                                )],
                                Json(json!(HeadResponse {
                                    slot,
                                    timestamp,
                                    timestamp_diff: (now - timestamp),
                                })),
                            )
                        }
                        Err(err) => {
                            tracing::error!("❌ Cannot get timestamp storage: {:?}", err);
                            if err.to_string().ends_with("status code: 429") {
                                (
                                    StatusCode::TOO_MANY_REQUESTS,
                                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                                    Json(json!({ "error": err.to_string()})),
                                )
                            } else {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                                    Json(json!({ "error": err.to_string()})),
                                )
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("❌ Cannot get head storage: {:?}", err.to_string());
                    if err.to_string().ends_with("status code: 429") {
                        (
                            StatusCode::TOO_MANY_REQUESTS,
                            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                            Json(json!({ "error": err.to_string()})),
                        )
                    } else {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                            Json(json!({ "error": err.to_string()})),
                        )
                    }
                }
            }
        }
        Err(err) => {
            tracing::error!(
                "Cannot get the latest finalized block hash: {:?}",
                err.to_string()
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": err.to_string()})),
            )
        }
    }
}

/// get_avl_head returns start and end blocks which the contract has commitments
#[inline(always)]
async fn get_avl_head(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let url = format!(
        "{}/{}/?contractChainId={}&contractAddress={}",
        state.succinct_base_url, "range", state.contract_chain_id, state.contract_address
    );
    let response = state.request_client.get(url).send().await;
    match response {
        Ok(ok) => {
            let range_response = ok.json::<RangeBlocksAPIResponse>().await;
            match range_response {
                Ok(range_blocks) => (
                    StatusCode::OK,
                    [(
                        "Cache-Control",
                        format!(
                            "public, max-age={}, must-revalidate",
                            state.avl_head_cache_maxage
                        ),
                    )],
                    Json(json!(range_blocks)),
                ),
                Err(err) => {
                    tracing::error!("❌ Cannot parse range blocks: {:?}", err.to_string());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                        Json(json!({ "error": err.to_string()})),
                    )
                }
            }
        }
        Err(err) => {
            tracing::error!("❌ Cannot get avl head: {:?}", err.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": err.to_string()})),
            )
        }
    }
}

#[inline(always)]
async fn get_transactions(
    State(state): State<Arc<AppState>>,
    Query(mut q): Query<TransactionQuery>,
) -> impl IntoResponse {
    // limit request page size to 100
    let page_size = q.page_size.unwrap_or(100);
    if page_size > 100 || page_size == 0 {
        q.page_size = Some(100);
    }

    if q.avail_address.is_none() && q.eth_address.is_none() {
        tracing::error!("❌ At least one address must be present in the query params.");
        return (
            StatusCode::BAD_REQUEST,
            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
            Json(
                json!({ "error": "At least one query address (avail_address, eth_address) must be present in the query params."}),
            ),
        );
    }

    if let Some(ref eth_address) = q.eth_address {
        if Address::parse_checksummed(eth_address.as_str(), None).is_err() {
            tracing::error!("❌ Provided Ethereum address is wrong: {:?}", eth_address);
            return (
                StatusCode::BAD_REQUEST,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": "Request cannot be fulfilled."})),
            );
        }
    }

    if let Some(ref avail_address) = q.avail_address {
        if AccountId32::from_ss58check_with_version(avail_address.as_str()).is_err() {
            tracing::error!("❌ Provided Avail address is wrong: {:?}", avail_address);
            return (
                StatusCode::BAD_REQUEST,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": "Request cannot be fulfilled."})),
            );
        }
    }

    let result_response = state
        .request_client
        .get(format!("{}/{}", state.indexer_base_url, "transactions"))
        .query(&q)
        .send()
        .await;

    match result_response {
        Ok(response) => {
            if response.status() != 200 {
                tracing::error!(
                    "❌ Cannot get transactions, status: {:?}",
                    response.status()
                );
                let mut status_code = StatusCode::INTERNAL_SERVER_ERROR;
                if response.status().is_client_error() {
                    status_code = StatusCode::NOT_FOUND;
                }

                return (
                    status_code,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": "Request cannot be fulfilled."})),
                );
            }

            let result = response.json::<Response>().await;
            match result {
                Ok(transactions) => (
                    StatusCode::OK,
                    [(
                        "Cache-Control",
                        format!(
                            "public, max-age={}, must-revalidate",
                            state.transactions_cache_maxage
                        ),
                    )],
                    Json(json!(transactions)),
                ),
                Err(err) => {
                    tracing::error!("❌ Cannot map transactions: {:?}", err.to_string());
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                        Json(json!({ "error": err.to_string()})),
                    )
                }
            }
        }
        Err(err) => {
            tracing::error!("❌ Cannot fetch transactions: {:?}", err.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                Json(json!({ "error": err.to_string()})),
            )
        }
    }
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "bridge_api=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .init();

    let max_concurrent_request: usize = env::var("MAX_CONCURRENT_REQUEST")
        .ok()
        .and_then(|max_request| max_request.parse::<usize>().ok())
        .unwrap_or(1024);

    let shared_state = Arc::new(AppState {
        avail_client: HttpClientBuilder::default()
            .max_concurrent_requests(max_concurrent_request)
            .build(
                env::var("AVAIL_CLIENT_URL")
                    .unwrap_or("https://avail-turing.public.blastapi.io/api".to_owned()),
            )
            .unwrap(),
        ethereum_client: HttpClientBuilder::default()
            .max_concurrent_requests(max_concurrent_request)
            .build(
                env::var("ETHEREUM_CLIENT_URL")
                    .unwrap_or("https://ethereum-sepolia.publicnode.com".to_owned()),
            )
            .unwrap(),
        request_client: Client::builder().brotli(true).build().unwrap(),
        succinct_base_url: env::var("SUCCINCT_URL")
            .unwrap_or("https://beaconapi.succinct.xyz/api/integrations/vectorx".to_owned()),
        beaconchain_base_url: env::var("BEACONCHAIN_URL")
            .unwrap_or("https://sepolia.beaconcha.in/api/v1/slot".to_owned()),
        indexer_base_url: env::var("INDEXER_BASE_URL")
            .unwrap_or("https://bridge-indie.slowops.xyz".to_owned()),
        contract_address: env::var("VECTORX_CONTRACT_ADDRESS")
            .unwrap_or("0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96".to_owned()),
        contract_chain_id: env::var("CONTRACT_CHAIN_ID").unwrap_or("11155111".to_owned()),
        avail_chain_name: env::var("AVAIL_CHAIN_NAME").unwrap_or("turing".to_owned()),
        bridge_contract_address: env::var("BRIDGE_CONTRACT_ADDRESS")
            .unwrap_or("0x967F7DdC4ec508462231849AE81eeaa68Ad01389".to_owned()),
        eth_head_cache_maxage: env::var("ETH_HEAD_CACHE_MAXAGE")
            .ok()
            .and_then(|max_request| max_request.parse::<u16>().ok())
            .unwrap_or(240),
        avl_head_cache_maxage: env::var("AVL_HEAD_CACHE_MAXAGE")
            .ok()
            .and_then(|max_request| max_request.parse::<u16>().ok())
            .unwrap_or(600),
        eth_proof_cache_maxage: env::var("ETH_PROOF_CACHE_MAXAGE")
            .ok()
            .and_then(|proof_response| proof_response.parse::<u32>().ok())
            .unwrap_or(172800),
        avl_proof_cache_maxage: env::var("AVL_PROOF_CACHE_MAXAGE")
            .ok()
            .and_then(|proof_response| proof_response.parse::<u32>().ok())
            .unwrap_or(172800),
        slot_mapping_cache_maxage: env::var("SLOT_MAPPING_CACHE_MAXAGE")
            .ok()
            .and_then(|slot_mapping_response| slot_mapping_response.parse::<u32>().ok())
            .unwrap_or(172800),
        transactions_cache_maxage: env::var("TRANSACTIONS_CACHE_MAXAGE")
            .ok()
            .and_then(|transactions_cache| transactions_cache.parse::<u32>().ok())
            .unwrap_or(1800),
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/info", get(info))
        .route("/eth/proof/:block_hash", get(get_eth_proof))
        .route("/eth/head", get(get_eth_head))
        .route("/avl/head", get(get_avl_head))
        .route("/avl/proof/:block_hash/:message_id", get(get_avl_proof))
        .route("/beacon/slot/:slot_number", get(get_beacon_slot))
        .route("/transactions", get(get_transactions))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_methods(vec![Method::GET])
                .allow_origin(Any),
        )
        .with_state(shared_state);

    let host = env::var("HOST").unwrap_or("0.0.0.0".to_owned());
    let port = env::var("PORT").unwrap_or("8080".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap();

    tracing::info!("🚀 Listening on {} port {}", host, port);
    axum::serve(listener, app).await.unwrap();
}

#[test]
fn exploration() {
    let add = "0xAfF84d35f9c784cE972A7Ff3e3E243E5eb6EF3".to_string();
    let avail = "4DyWPc4JfC9c3Awp3D8e7HH5UDg4nKGEsumUHcB8pwBpBe1B".to_string();

    if Address::parse_checksummed(add, None).is_ok() {
        println!("Address is OK");
    } else {
        println!("Address is NOT OK")
    }

    if AccountId32::from_ss58check_with_version(avail.as_str()).is_ok() {
        println!("AVAIL Address is OK");
    } else {
        println!("AVAIL Address is NOT OK")
    }
}
