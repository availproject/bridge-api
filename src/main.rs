mod models;
mod schema;
use diesel::{r2d2, QueryDsl, SelectableHelper};

use crate::models::{AvailSend, EthereumSend, StatusEnum};
use crate::schema::avail_sends::dsl::avail_sends;
use crate::schema::ethereum_sends::dsl::ethereum_sends;
use alloy_primitives::{hex, B256, U256};
use anyhow::{Context, Result};
use avail_core::data_proof::AddressedMessage;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use backon::ExponentialBuilder;
use backon::Retryable;
use chrono::{NaiveDateTime, Utc};
use diesel::r2d2::ConnectionManager;
use diesel::ExpressionMethods;
use diesel::{PgConnection, RunQueryDsl};
use http::Method;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_with::serde_as;
use sha3::{Digest, Keccak256};
use sp_core::{Decode, H160, H256};
use sp_io::hashing::twox_128;
use std::sync::Arc;
use std::{env, process, time::Duration};
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tokio::{join, sync::RwLock};
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
    beaconchain_api_key: String,
    connection_pool: r2d2::Pool<ConnectionManager<PgConnection>>,
}

#[derive(Deserialize)]
struct IndexStruct {
    index: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct KateQueryDataProofResponse {
    data_proof: DataProof,
    #[serde(skip_serializing_if = "Option::is_none")]
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
struct HeadResponseV2 {
    pub slot: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub timestamp: u64,
    pub timestamp_diff: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeadResponseLegacy {
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
async fn versions(State(_state): State<Arc<AppState>>) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!(["v1"])))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionQueryParams {
    eth_address: Option<H160>,
    avail_address: Option<H256>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde_as]
#[serde(rename_all = "camelCase")]
pub struct TransactionData {
    pub message_id: i64,
    pub status: StatusEnum,
    pub source_transaction_hash: String,
    pub source_block_number: i64,
    pub source_block_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_transaction_index: Option<i64>,
    #[serde_as(as = "TimestampSeconds")]
    pub source_timestamp: NaiveDateTime,
    pub token_id: String,
    pub destination_block_number: Option<i64>,
    pub destination_block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_transaction_index: Option<i64>,
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub destination_timestamp: Option<NaiveDateTime>,
    pub depositor_address: String,
    pub receiver_address: String,
    pub amount: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResult {
    pub avail_send: Vec<TransactionData>,
    pub eth_send: Vec<TransactionData>,
}

fn map_ethereum_send_to_transaction_result(send: EthereumSend) -> TransactionData {
    TransactionData {
        message_id: send.message_id,
        status: send.status,
        source_transaction_hash: send.source_transaction_hash,
        source_block_number: send.source_block_number,
        source_block_hash: send.source_block_hash,
        source_transaction_index: None,
        source_timestamp: send.source_timestamp,
        token_id: send.token_id,
        destination_block_number: send.destination_block_number,
        destination_block_hash: send.destination_block_hash,
        destination_transaction_index: send.destination_transaction_index,
        destination_timestamp: send.destination_timestamp,
        depositor_address: send.depositor_address,
        receiver_address: send.receiver_address,
        amount: send.amount,
    }
}

// Function to map AvailSend to TransactionResult
fn map_avail_send_to_transaction_result(send: AvailSend) -> TransactionData {
    TransactionData {
        message_id: send.message_id,
        status: send.status,
        source_transaction_hash: send.source_transaction_hash,
        source_block_number: send.source_block_number,
        source_block_hash: send.source_block_hash,
        source_transaction_index: Some(send.source_transaction_index),
        source_timestamp: send.source_timestamp,
        token_id: send.token_id,
        destination_block_number: send.destination_block_number,
        destination_block_hash: send.destination_block_hash,
        destination_transaction_index: None,
        destination_timestamp: send.destination_timestamp,
        depositor_address: send.depositor_address,
        receiver_address: send.receiver_address,
        amount: send.amount,
    }
}

#[inline(always)]
async fn transactions(
    Query(address_query): Query<TransactionQueryParams>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if address_query.eth_address.is_none() && address_query.avail_address.is_none() {
        tracing::error!("Query params not provided.");
        return (
            StatusCode::BAD_REQUEST,
            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
            Json(json!({ "error": "Invalid request: Query params not provided"})),
        );
    }

    let cloned_state = state.clone();
    let mut conn = cloned_state
        .connection_pool
        .get_timeout(Duration::from_secs(1))
        .expect("Get connection pool");

    // Initialize the result variables
    let mut transaction_results: TransactionResult = TransactionResult::default();

    // Return the combined results
    if let Some(eth_address) = address_query.eth_address {
        let ethereum_sends_results = ethereum_sends
            .select(EthereumSend::as_select())
            .filter(schema::ethereum_sends::depositor_address.eq(format!("{:?}", eth_address)))
            .order_by(schema::ethereum_sends::source_timestamp.desc())
            .limit(500)
            .load::<EthereumSend>(&mut conn);

        match ethereum_sends_results {
            Ok(transaction) => {
                transaction_results.eth_send = transaction
                    .into_iter()
                    .map(map_ethereum_send_to_transaction_result)
                    .collect()
            }
            Err(e) => {
                tracing::error!("Cannot get ethereum send transactions: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": e.to_string()})),
                );
            }
        }
    }
    if let Some(avail_address) = address_query.avail_address {
        let avail_sends_results = avail_sends
            .select(AvailSend::as_select())
            .filter(schema::avail_sends::depositor_address.eq(format!("{:?}", avail_address)))
            .order_by(schema::avail_sends::source_timestamp.desc())
            .limit(500)
            .load::<AvailSend>(&mut conn);

        match avail_sends_results {
            Ok(transaction) => {
                transaction_results.avail_send = transaction
                    .into_iter()
                    .map(map_avail_send_to_transaction_result)
                    .collect()
            }
            Err(e) => {
                tracing::error!("Cannot get avail send transactions: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                    Json(json!({ "error": e.to_string()})),
                );
            }
        }
    }

    (
        StatusCode::OK,
        [(
            "Cache-Control",
            format!(
                "public, max-age={}, immutable",
                state.transactions_cache_maxage
            ),
        )],
        Json(json!(transaction_results)),
    )
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
                return match data.to_string().contains("is not in the range of blocks") {
                    true => {
                        tracing::warn!(
                            "⏳ Succinct VectorX contract not updated yet! Response: {}",
                            data
                        );
                        (
                            StatusCode::TOO_EARLY,
                            [(
                                "Cache-Control",
                                format!("max-age={}, must-revalidate", eth_proof_cache_maxage),
                            )],
                            Json(json!({ "error": data })),
                        )
                    }
                    _ => {
                        tracing::error!(
                            "❌ Succinct API returned unsuccessfully. Response: {}",
                            data
                        );
                        (
                            StatusCode::NOT_FOUND,
                            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
                            Json(json!({ "error": data })),
                        )
                    }
                }
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
    Path((block_hash, message_id_query)): Path<(B256, U256)>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut hasher = Keccak256::new();
    hasher.update(
        [
            message_id_query.to_be_bytes_vec(),
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
        .header("apikey", state.beaconchain_api_key.clone())
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
    let slot_block_head = SLOT_BLOCK_HEAD.read().await;
    if let Some((slot, block, hash, timestamp)) = slot_block_head.as_ref() {
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
            Json(json!(HeadResponseV2 {
                slot: *slot,
                block_number: *block,
                block_hash: *hash,
                timestamp: *timestamp,
                timestamp_diff: now - *timestamp
            })),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
            Json(json!({ "error": "Not found"})),
        )
    }
}

/// get_eth_head returns Ethereum head with the latest slot/block that is stored and a time.
#[inline(always)]
async fn get_eth_head_legacy(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let slot_block_head = SLOT_BLOCK_HEAD.read().await;
    if let Some((slot, _block, _hash, timestamp)) = slot_block_head.as_ref() {
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
            Json(json!(HeadResponseLegacy {
                slot: *slot,
                timestamp: *timestamp,
                timestamp_diff: now - *timestamp
            })),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Cache-Control", "max-age=60, must-revalidate".to_string())],
            Json(json!({ "error": "Not found"})),
        )
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
        env::var("PG_USERNAME").unwrap_or("myuser".to_owned()),
        env::var("PG_PASSWORD").unwrap_or("mypassword".to_owned()),
        env::var("POSTGRES_URL").unwrap_or("localhost:5432".to_owned()),
        env::var("POSTGRES_DB").unwrap_or("bridge-ui-indexer".to_owned()),
    );
    let connection_pool = r2d2::Pool::builder()
        .build(ConnectionManager::<PgConnection>::new(connections_string))
        .expect("Failed to create pool.");

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
            .and_then(|transactions_mapping_response| {
                transactions_mapping_response.parse::<u32>().ok()
            })
            .unwrap_or(60),
        beaconchain_api_key: env::var("BEACONCHAIN_API_KEY").unwrap_or("".to_owned()),
        connection_pool,
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/versions", get(versions))
        .route("/v1/info", get(info))
        .route("/info", get(info))
        .route("/v1/eth/proof/:block_hash", get(get_eth_proof))
        .route("/eth/proof/:block_hash", get(get_eth_proof))
        .route("/v1/eth/head", get(get_eth_head))
        .route("/eth/head", get(get_eth_head_legacy))
        .route("/v1/avl/head", get(get_avl_head))
        .route("/avl/head", get(get_avl_head))
        .route("/v1/avl/proof/:block_hash/:message_id", get(get_avl_proof))
        .route("/v1/transactions", get(transactions))
        .route("/transactions", get(transactions))
        .route("/avl/proof/:block_hash/:message_id", get(get_avl_proof))
        .route("/beacon/slot/:slot_number", get(get_beacon_slot))
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
            process::exit(-1);
        }
    });
    tracing::info!("🚀 Listening on {} port {}", host, port);
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

                let resp = reqwest::get(format!("{}/{}", state.beaconchain_base_url, slot))
                    .await
                    .context("beacon get")?;
                let res = resp
                    .json::<BeaconAPIResponse>()
                    .await
                    .context("beacon decode")?;
                let bl = res.data.exec_block_number;
                let h = res.data.exec_block_hash;
                let mut slot_block_head = SLOT_BLOCK_HEAD.write().await;
                tracing::info!("Beacon mapping: {slot}:{bl}");
                *slot_block_head = Some((slot, bl as u64, h, timestamp));
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
