mod models;
use crate::AvailBridge::{AvailBridgeCalls, AvailBridgeEvents};
use crate::models::*;

use alloy::primitives::{Address, B256, U256, hex};
use alloy::providers::ProviderBuilder;
use alloy::sol_types::{SolEventInterface, SolInterface};
use anyhow::{Context, Result, anyhow};
use axum::body::{Body, to_bytes};
use axum::response::Response;
use axum::routing::post;
use axum::{
    Router,
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use backon::ExponentialBuilder;
use backon::Retryable;
use chrono::Utc;
use sp_core::hexdisplay::AsBytesRef;

use crate::models::TxDirection::{AvailEth, EthAvail};
use alloy::core::sol;
use alloy::rpc::types::TransactionReceipt;
use bigdecimal::BigDecimal;
use http::Method;
use jsonrpsee::{
    core::ClientError,
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use lazy_static::lazy_static;
use reqwest::Client;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use sp_core::Decode;
use sp_io::hashing::twox_128;
use sqlx::{PgPool, query};
use std::collections::HashMap;
use std::ops::Sub;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, process, time::Duration};
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tokio::task::JoinHandle;
use tokio::{join, sync::RwLock};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::prelude::*;

sol! {
    #[derive(Debug)]
    contract AvailBridge {
        function sendAVAIL(bytes32 recipient, uint256 amount) external;
        event MessageSent(address indexed from, bytes32 indexed to, uint256 messageId);
    }
}

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Debug)]
pub struct AppState {
    pub avail_client: HttpClient,
    pub ethereum_client: HttpClient,
    pub request_client: Client,
    pub merkle_proof_service_base_url: String,
    pub beaconchain_base_url: String,
    pub avail_chain_name: String,
    pub contract_chain_id: String,
    pub contract_address: String,
    pub bridge_contract_address: String,
    pub eth_head_cache_maxage: u16,
    pub avl_head_cache_maxage: u16,
    pub head_cache_maxage: u16,
    pub avl_proof_cache_maxage: u32,
    pub eth_proof_cache_maxage: u32,
    pub proof_cache_maxage: u32,
    pub eth_proof_failure_cache_maxage: u32,
    pub slot_mapping_cache_maxage: u32,
    pub transactions_cache_maxage: u32,
    pub db: PgPool,
    pub chains: HashMap<u64, Chain>,
    pub helios_update_frequency: u32,
    pub vector_update_frequency: u32,
}

async fn alive() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({ "name": "Avail Bridge API" })))
}

#[inline(always)]
async fn transaction(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<B256>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let tx: TransactionRpc = state
        .ethereum_client
        .request("eth_getTransactionByHash", rpc_params![hash])
        .await
        .map_err(|e| {
            tracing::error!("Cannot get transaction: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Cannot get transaction"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    let receipt: TransactionReceipt = state
        .ethereum_client
        .request("eth_getTransactionReceipt", rpc_params![hash])
        .await
        .map_err(|e| {
            tracing::error!("Cannot get transaction receipt: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Cannot get transaction receipt"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    let AvailBridgeCalls::sendAVAIL(call) =
        AvailBridge::AvailBridgeCalls::abi_decode(hex::decode(tx.input)?.as_bytes_ref())?;

    let recipient = format!("0x{}", hex::encode(*call.recipient));
    let amount = call.amount;
    let a = format!("{:x}", amount);
    let av = u128::from_str_radix(&a, 16).map_err(|e| {
        tracing::error!("Cannot parse amount: {e:#}");
        ErrorResponse::with_status(
            anyhow!("Cannot fetch valid transaction data"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })?;

    let target_topic =
        B256::from_str("0x06fd209663be9278f96bc53dfbf6cf3cdcf2172c38b5de30abff93ba443d653a")?;

    let log = receipt
        .inner
        .logs()
        .iter()
        .find(|log| log.topics().contains(&target_topic))
        .ok_or_else(|| anyhow!("Cannot find transaction log"))?
        .clone()
        .into();

    let decoded = AvailBridgeEvents::decode_log(&log)?;
    let AvailBridgeEvents::MessageSent(call) = decoded.data;
    let message_id: i64 = call.messageId.try_into()?;

    query(
        "INSERT INTO bridge_event (
                            message_id,
                            event_type,
                            status,
                            sender,
                            receiver,
                            amount,
                            source_block_hash,
                            block_number,
                            source_transaction_hash
                            ) VALUES(
                                  $1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(message_id)
    .bind("MessageSent")
    .bind(BridgeStatusEnum::Initialized)
    .bind(tx.from)
    .bind(recipient)
    .bind(BigDecimal::from(av))
    .bind(tx.block_hash)
    .bind(tx.block_number as i32)
    .bind(tx.hash)
    .execute(&state.db)
    .await
    .map_err(|e| {
        warn!("Cannot insert tx {}", e);
        return anyhow!("Cannot insert tx");
    })?;

    Ok(())
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
async fn versions(State(_state): State<Arc<AppState>>) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!(["v1"])))
}

#[inline(always)]
async fn transactions(
    Query(address_query): Query<TransactionQueryParams>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Transaction query: {:?}", address_query);

    // check provided params
    if address_query.eth_address.is_none() && address_query.avail_address.is_none() {
        tracing::error!("Query params not provided.");
        return Err(ErrorResponse::with_status_and_headers(
            anyhow!("Invalid request: Query params not provided"),
            StatusCode::BAD_REQUEST,
            &[("Cache-Control", "max-age=60, must-revalidate")],
        ));
    }

    let avail_finalized_block: u32 = state
        .avail_client
        .request("chain_getFinalizedHead", rpc_params![])
        .await
        .context("finalized head")
        .unwrap_or(0);

    let mut transaction_results: Vec<TransactionData> = vec![];

    if let Some(eth_address) = address_query.eth_address {
        let rows: Vec<TransactionRow> =
            sqlx::query_as::<_, TransactionRow>(include_str!("query_eth_tx.sql"))
                .bind(format!("{:?}", eth_address))
                .bind("MessageSent")
                .fetch_all(&state.db)
                .await?;

        let slot_block_head = SLOT_BLOCK_HEAD.read().await;
        let (_slot, block, _hash, timestamp) = slot_block_head.as_ref().ok_or_else(|| {
            ErrorResponse::with_status(anyhow!("Not found"), StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        let claim_estimate =
            time_until_next_helios_update(*timestamp, state.helios_update_frequency);

        for mut r in rows {
            let mut estimate = None;
            if r.final_status != BridgeStatusEnum::Bridged && r.block_height <= *block as i32 {
                r.final_status = BridgeStatusEnum::ClaimReady
            } else if r.final_status != BridgeStatusEnum::Bridged
                && r.final_status != BridgeStatusEnum::ClaimReady
            {
                estimate = Some(claim_estimate.as_secs());
            }

            let tx = TransactionData::new(
                EthAvail,
                r.message_id,
                r.sender,
                r.receiver,
                r.source_block_hash,
                r.source_transaction_hash,
                r.amount,
                r.final_status,
                estimate,
                r.block_height,
                None,
            );
            transaction_results.push(tx);
        }
    }

    if let Some(avail_address) = address_query.avail_address {
        let rows: Vec<TransactionRow> =
            sqlx::query_as::<_, TransactionRow>(include_str!("query_avail_tx.sql"))
                .bind(avail_address)
                .bind("FungibleToken")
                .bind("MessageReceived")
                .bind(true)
                .fetch_all(&state.db)
                .await?;

        let url = format!(
            "{}/api/{}?chainName={}&contractChainId={}&contractAddress={}",
            state.merkle_proof_service_base_url,
            "range",
            state.avail_chain_name,
            state.contract_chain_id,
            state.contract_address
        );

        let response = state.request_client.get(url).send().await.map_err(|e| {
            tracing::error!("❌ Cannot parse range blocks: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow!("{e:#}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

        let range_blocks = response
            .json::<RangeBlocksAPIResponse>()
            .await
            .map_err(|e| {
                tracing::error!("❌ Cannot parse range blocks: {e:#}");
                ErrorResponse::with_status_and_headers(
                    anyhow!("{e:#}"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &[("Cache-Control", "public, max-age=60, must-revalidate")],
                )
            })?;

        let claim_estimate = remaining_time_seconds(
            avail_finalized_block,
            range_blocks.data.end,
            state.vector_update_frequency,
            20,
        );
        let avail_send: Vec<TransactionData> = Vec::new();

        for mut r in rows {
            let mut estimate = None;

            if r.final_status == BridgeStatusEnum::InProgress
                && r.block_height < range_blocks.data.end as i32
            {
                r.final_status = BridgeStatusEnum::ClaimReady;
            } else if r.final_status == BridgeStatusEnum::Initialized
                || r.final_status == BridgeStatusEnum::InProgress
            {
                estimate = Some(claim_estimate.as_secs());
            }

            let tx = TransactionData::new(
                AvailEth,
                r.message_id,
                r.sender,
                r.receiver,
                r.source_block_hash,
                r.source_transaction_hash,
                r.amount,
                r.final_status,
                estimate,
                r.block_height,
                r.ext_index,
            );

            transaction_results.push(tx);
        }
    }

    Ok(Json(json!(transaction_results)))
}

fn remaining_time_seconds(
    current_block: u32,
    last_updated_block: u32,
    blocks_per_update: u32,
    block_time_seconds: u32,
) -> Duration {
    let blocks_since_update = current_block.saturating_sub(last_updated_block);
    let blocks_remaining = blocks_per_update.saturating_sub(blocks_since_update);

    Duration::from_secs((blocks_remaining * block_time_seconds) as u64)
}

fn time_until_next_helios_update(timestamp_ms: u64, heliso_update_frequency: u32) -> Duration {
    let now = Utc::now().timestamp() as u64;
    let time_since_update = now - timestamp_ms;
    let update_frequency = Duration::from_secs(heliso_update_frequency as u64).as_secs();
    let remaining = update_frequency.saturating_sub(time_since_update);
    Duration::from_secs(remaining)
}

#[inline(always)]
async fn get_eth_proof(
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
                anyhow::anyhow!("Something went wrong."),
                StatusCode::BAD_REQUEST,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

    let merkle_proof_data = merkle_proof_response
        .map_err(|e| {
            tracing::error!("❌ Failed to get the merkle proof data. Error: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow::anyhow!("Something went wrong."),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?
        .map_err(|e| {
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
                tracing::warn!(
                    "⏳ Merkle proof VectorX contract not updated yet! Response: {}",
                    data
                );
            } else {
                tracing::error!("❌ Merkle API returned unsuccessfully. Response: {}", data);
            }

            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("{data}"),
                StatusCode::NOT_FOUND,
                &[(
                    "Cache-Control",
                    &format!("public, max-age={eth_proof_failure_cache_maxage}, must-revalidate"),
                )],
            ));
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

#[inline(always)]
async fn get_avl_proof(
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
    let mut resp = proof.map_err(|e| {
        tracing::error!("❌ Cannot get account and storage proofs: {e:#}");
        if e.to_string().ends_with("status code: 429") {
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
            storage_proof: resp.storage_proof.swap_remove(0).proof,
        })),
    )
        .into_response())
}

/// get_eth_head returns Ethereum head with the latest slot/block that is stored and a time.
#[inline(always)]
async fn get_eth_head(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let slot_block_head = SLOT_BLOCK_HEAD.read().await;
    let (slot, block, hash, timestamp) = slot_block_head.as_ref().ok_or_else(|| {
        ErrorResponse::with_status_and_headers(
            anyhow!("Not found"),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "public, max-age=60, must-revalidate")],
        )
    })?;

    let now = Utc::now().timestamp() as u64;
    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!(
                "public, max-age={}, must-revalidate",
                state.eth_head_cache_maxage
            ),
        )],
        Json(json!(HeadResponseV2 {
            slot: *slot,
            block_number: *block,
            block_hash: *hash,
            timestamp: *timestamp,
            timestamp_diff: now - *timestamp
        })),
    )
        .into_response())
}

/// get_avl_head returns start and end blocks which the contract has commitments
#[inline(always)]
async fn get_avl_head(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let url = format!(
        "{}/{}/?contractChainId={}&contractAddress={}",
        state.merkle_proof_service_base_url,
        "range",
        state.contract_chain_id,
        state.contract_address
    );
    let response = state.request_client.get(url).send().await.map_err(|e| {
        tracing::error!("❌ Cannot parse range blocks: {e:#}");
        ErrorResponse::with_status_and_headers(
            anyhow!("{e:#}"),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "public, max-age=60, must-revalidate")],
        )
    })?;

    let range_blocks = response
        .json::<RangeBlocksAPIResponse>()
        .await
        .map_err(|e| {
            tracing::error!("❌ Cannot parse range blocks: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow!("{e:#}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!(
                "public, max-age={}, must-revalidate",
                state.avl_head_cache_maxage
            ),
        )],
        Json(json!(range_blocks)),
    )
        .into_response())
}

#[inline(always)]
async fn get_head(
    Path(chain_id): Path<u64>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let chain = state.chains.get(&chain_id).ok_or_else(|| {
        ErrorResponse::with_status_and_headers(
            anyhow!("Unsupported chain ID"),
            StatusCode::BAD_REQUEST,
            &[("Cache-Control", "public, max-age=3600, must-revalidate")],
        )
    })?;

    let provider = ProviderBuilder::new()
        .connect(&chain.rpc_url)
        .await
        .map_err(|e| {
            tracing::error!("❌ Cannot connect to provider: {:?}", e);
            ErrorResponse::with_status_and_headers(
                anyhow!("{e:#}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;
    let contract = SP1Vector::new(chain.contract_address, provider);
    let head = contract.latestBlock().call().await.map_err(|e| {
        tracing::error!("❌ Cannot get latest block from contract: {:?}", e);
        ErrorResponse::with_status_and_headers(
            anyhow!("{e:#}"),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "public, max-age=60, must-revalidate")],
        )
    })?;

    tracing::debug!("✅ Latest block on chain {}: {}", chain_id, head);
    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!(
                "public, max-age={}, must-revalidate",
                state.head_cache_maxage
            ),
        )],
        Json(json!(ChainHeadResponse { head })),
    )
        .into_response())
}

/// get_proof returns a proof from Avail for the provided chain id
#[inline(always)]
async fn get_proof(
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
        Err(err) => {
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

    // Connection pool
    let connections_string = format!(
        "postgresql://{}:{}@{}/{}",
        env::var("PG_USERNAME").unwrap_or("avail".to_owned()),
        env::var("PG_PASSWORD").unwrap_or("avail".to_owned()),
        env::var("POSTGRES_URL").unwrap_or("localhost:5432".to_owned()),
        env::var("POSTGRES_DB").unwrap_or("ui-indexer".to_owned()),
    );

    info!("Connecting to {}", connections_string);

    let db = PgPool::connect(&connections_string)
        .await
        .context("Cannot get connection pool")
        .unwrap();

    const SUPPORTED_CHAIN_IDS: [u64; 7] = [1, 123, 32657, 84532, 11155111, 17000, 421614];
    // loop through expected_chain_ids and store the chain information, if value is missing, skip chain_id
    let chains = SUPPORTED_CHAIN_IDS
        .iter()
        .filter_map(|&chain_id| {
            let rpc_url = env::var(format!("CHAIN_{}_RPC_URL", chain_id)).ok()?;
            let contract_address = env::var(format!("CHAIN_{}_CONTRACT_ADDRESS", chain_id))
                .ok()
                .and_then(|addr| addr.parse::<Address>().ok())?;
            Some((
                chain_id,
                Chain {
                    rpc_url,
                    contract_address,
                },
            ))
        })
        .collect::<HashMap<_, _>>();

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
        merkle_proof_service_base_url: env::var("MERKLE_PROOF_SERVICE_URL")
            .unwrap_or("https://beaconapi.succinct.xyz/api/integrations/vectorx".to_owned()),
        beaconchain_base_url: env::var("BEACONCHAIN_URL")
            .unwrap_or("https://sepolia.beaconcha.in/api/v1/slot".to_owned()),
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
        head_cache_maxage: env::var("HEAD_CACHE_MAXAGE")
            .ok()
            .and_then(|max_request| max_request.parse::<u16>().ok())
            .unwrap_or(60),
        eth_proof_cache_maxage: env::var("ETH_PROOF_CACHE_MAXAGE")
            .ok()
            .and_then(|proof_response| proof_response.parse::<u32>().ok())
            .unwrap_or(172800),
        proof_cache_maxage: env::var("PROOF_CACHE_MAXAGE")
            .ok()
            .and_then(|proof_response| proof_response.parse::<u32>().ok())
            .unwrap_or(172800),
        eth_proof_failure_cache_maxage: env::var("ETH_PROOF_FAILURE_CACHE_MAXAGE")
            .ok()
            .and_then(|proof_response| proof_response.parse::<u32>().ok())
            .unwrap_or(5400),
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
            .and_then(|transactions_mapping_response| {
                transactions_mapping_response.parse::<u32>().ok()
            })
            .unwrap_or(60),
        db,
        chains,
        helios_update_frequency: env::var("HELIOS_UPDATE_FREQUENCY")
            .ok()
            .and_then(|helios_update_frequency| helios_update_frequency.parse::<u32>().ok())
            .unwrap_or(3600),
        vector_update_frequency: env::var("VECTOR_UPDATE_FREQUENCY")
            .ok()
            .and_then(|vector_update_frequency| vector_update_frequency.parse::<u32>().ok())
            .unwrap_or(360),
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/versions", get(versions))
        .route("/v1/info", get(info))
        .route("/v2/transaction/{txHash}", post(transaction))
        .route("/v1/eth/proof/{block_hash}", get(get_eth_proof)) // get proof from avail for ethereum
        .route("/v1/eth/head", get(get_eth_head)) // fetch head form eth contract
        .route("/v1/avl/head", get(get_avl_head)) // fetch head form avail pallet
        .route(
            "/v1/avl/proof/{block_hash}/{message_id}",
            get(get_avl_proof), // get proof from ethereum for avail
        )
        .route("/v1/transactions", get(transactions)) // fetch all transaction
        .route("/transactions", get(transactions))
        .route("/v1/head/{chain_id}", get(get_head)) // get head based on chain
        .route("/v1/proof/{chain_id}", get(get_proof)) // get proof for avail based on chain
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_methods(vec![Method::GET])
                .allow_origin(Any),
        )
        .with_state(shared_state.clone());

    let host = env::var("HOST").unwrap_or("0.0.0.0".to_owned());
    let port = env::var("PORT").unwrap_or("8080".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap();

    tokio::spawn(async move {
        tracing::info!("Starting head tracking task");
        if let Err(e) = track_slot_avail_task(shared_state.clone()).await {
            tracing::error!("Error occurred, cannot continue: {e:#}");
            process::exit(1);
        }
    });
    tracing::info!("🚀 Started server on host {} with port {}", host, port);
    axum::serve(listener, app).await.unwrap();
}

lazy_static! {
    static ref SLOT_BLOCK_HEAD: RwLock<Option<(u64, u64, B256, u64)>> = RwLock::new(None);
}

async fn track_slot_avail_task(state: Arc<AppState>) -> Result<()> {
    let pallet = "Vector";
    let head = "Head";
    let timestamp = "Timestamps";

    let do_work = || {
        let state = state.clone();
        async move {
            loop {
                let finalized_block_hash_str: String = state
                    .avail_client
                    .request("chain_getFinalizedHead", rpc_params![])
                    .await
                    .context("finalized head")?;

                let head_key = format!(
                    "0x{}{}",
                    hex::encode(twox_128(pallet.as_bytes())),
                    hex::encode(twox_128(head.as_bytes()))
                );
                let head_str: String = state
                    .avail_client
                    .request(
                        "state_getStorage",
                        rpc_params![head_key, finalized_block_hash_str.clone()],
                    )
                    .await
                    .context("head key")?;

                let slot_from_hex =
                    sp_core::bytes::from_hex(head_str.as_str()).context("decode slot")?;
                let slot: u64 =
                    Decode::decode(&mut slot_from_hex.as_slice()).context("slot decode 2")?;

                let timestamp_key = format!(
                    "0x{}{}{}",
                    hex::encode(twox_128(pallet.as_bytes())),
                    hex::encode(twox_128(timestamp.as_bytes())),
                    &head_str[2..].to_string()
                );

                let timestamp_str: String = state
                    .avail_client
                    .request(
                        "state_getStorage",
                        rpc_params![timestamp_key, finalized_block_hash_str],
                    )
                    .await
                    .context("timestamp key")?;

                let timestamp_from_hex =
                    sp_core::bytes::from_hex(timestamp_str.as_str()).context("timestamp decode")?;

                let timestamp: u64 = Decode::decode(&mut timestamp_from_hex.as_slice())
                    .context("timestamp decode 2")?;

                let slot_block_head = SLOT_BLOCK_HEAD.read().await;
                if let Some((old_slot, _old_block, _old_hash, _old_timestamp)) =
                    slot_block_head.as_ref()
                {
                    if old_slot == &slot {
                        tokio::time::sleep(Duration::from_secs(60 * 10)).await;
                        continue;
                    }
                }

                drop(slot_block_head);

                let response = reqwest::get(format!(
                    "{}/eth/v2/beacon/blocks/{}",
                    state.beaconchain_base_url, slot
                ))
                .await
                .context("Cannot get beacon block")?;
                let root = response
                    .json::<Root>()
                    .await
                    .context("Cannot decode beacon response")?;
                let bl = root
                    .data
                    .message
                    .body
                    .execution_payload
                    .block_number
                    .parse()?;
                let hash = root
                    .data
                    .message
                    .body
                    .execution_payload
                    .block_hash
                    .parse()?;
                let mut slot_block_head = SLOT_BLOCK_HEAD.write().await;
                tracing::info!("Beacon mapping: {slot}:{bl}");
                *slot_block_head = Some((slot, bl, hash, timestamp));
                info!("Timestamp form task: {:?}", timestamp);

                drop(slot_block_head);

                tokio::time::sleep(Duration::from_secs(60 * 5)).await;
            }
            #[allow(unreachable_code)] // forces for type inference later on
            Ok::<(), anyhow::Error>(())
        }
    };

    let retry_settings = ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(5))
        .with_max_delay(Duration::from_secs(60))
        .with_max_times(10)
        .with_factor(2.0);
    do_work.retry(&retry_settings).await?;

    Ok(())
}

#[test]
fn test_remaining_time_for_vector_update() {
    let d = remaining_time_seconds(350, 50, 360, 20);
    assert_eq!(1200, d.as_secs());
    let d = remaining_time_seconds(100, 50, 360, 20);
    assert_eq!(6200, d.as_secs());
}

#[test]
fn test_remaining_time_for_helios_update() {
    let update = Utc::now().timestamp() - 1200;
    let remaining = time_until_next_helios_update(update as u64);
    assert_eq!(2400, remaining.as_secs());
}
