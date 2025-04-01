mod models;
mod schema;

use crate::models::{AvailSend, EthereumSend, StatusEnum};
use crate::schema::avail_sends::dsl::avail_sends;
use crate::schema::ethereum_sends::dsl::ethereum_sends;
use alloy::primitives::{Address, B256, U256, hex};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use anyhow::{Context, Result, anyhow};
use avail_core::data_proof::AddressedMessage;
use axum::body::{Body, to_bytes};
use axum::response::Response;
use axum::{
    Router,
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use backon::ExponentialBuilder;
use backon::Retryable;
use chrono::{NaiveDateTime, Utc};
use diesel::{
    ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl, SelectableHelper, r2d2,
    r2d2::ConnectionManager,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use jsonrpsee::{
    core::ClientError,
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use serde_with::serde_as;
use sha3::{Digest, Keccak256};
use sp_core::{Decode, H160, H256};
use sp_io::hashing::twox_128;
use std::collections::HashMap;
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
use tracing::warn;
use tracing_subscriber::prelude::*;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1Vector,
    "src/abi/SP1Vector.json"
);

#[derive(Debug, Deserialize)]
struct Root {
    data: Data,
}

#[derive(Debug, Deserialize)]
struct Data {
    message: Message,
}

#[derive(Debug, Deserialize)]
struct Message {
    slot: String,
    body: MessageBody,
}

#[derive(Debug, Deserialize)]
struct MessageBody {
    execution_payload: ExecutionPayload,
}

#[derive(Debug, Deserialize)]
struct ExecutionPayload {
    block_number: String,
    block_hash: String,
}

struct ErrorResponse {
    pub error: anyhow::Error,
    pub headers_keypairs: Vec<(String, String)>,
    pub status_code: Option<StatusCode>,
}

impl ErrorResponse {
    pub fn new(error: anyhow::Error) -> Self {
        Self {
            error,
            headers_keypairs: vec![],
            status_code: None,
        }
    }
    pub fn with_status(error: anyhow::Error, status_code: StatusCode) -> Self {
        Self {
            error,
            headers_keypairs: vec![],
            status_code: Some(status_code),
        }
    }

    pub fn with_status_and_headers(
        error: anyhow::Error,
        status_code: StatusCode,
        headers: &[(&str, &str)],
    ) -> Self {
        let h = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>();
        Self {
            error,
            headers_keypairs: h,
            status_code: Some(status_code),
        }
    }
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = self
            .status_code
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut headermap = HeaderMap::new();
        for (k, v) in self.headers_keypairs {
            headermap.insert(
                HeaderName::try_from(k).unwrap(),
                HeaderValue::try_from(v).unwrap(),
            );
        }
        let json_resp = Json(json!({"error" : format!("{:#}", self.error)}));

        (status, headermap, json_resp).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for ErrorResponse
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self {
            error: err.into(),
            headers_keypairs: vec![],
            status_code: None,
        }
    }
}

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
    head_cache_maxage: u16,
    avl_proof_cache_maxage: u32,
    eth_proof_cache_maxage: u32,
    proof_cache_maxage: u32,
    eth_proof_failure_cache_maxage: u32,
    slot_mapping_cache_maxage: u32,
    transactions_cache_maxage: u32,
    connection_pool: r2d2::Pool<ConnectionManager<PgConnection>>,
    transactions_result_max_size: u32,
    chains: HashMap<u64, Chain>,
}

#[derive(Debug)]
struct Chain {
    rpc_url: String,
    contract_address: Address,
}

#[derive(Deserialize)]
struct IndexStruct {
    index: u32,
}

#[derive(Deserialize)]
struct ProofQueryStruct {
    index: u32,
    block_hash: B256,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SlotMappingResponse {
    block_hash: String,
    block_number: String,
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

impl AggregatedResponse {
    pub fn new(
        range_data: SuccinctAPIData,
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
struct ChainHeadResponse {
    pub head: u32,
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

#[derive(Debug, Deserialize)]
pub struct HeaderBlockNumber {
    #[serde(deserialize_with = "hex_to_u32")]
    pub number: u32,
}

fn hex_to_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    u32::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
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

/// transactions returns bridge transactions that are matched with a provided query params
/// limits the output to the most recent (500 default) transaction.
#[inline(always)]
async fn transactions(
    Query(address_query): Query<TransactionQueryParams>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    if address_query.eth_address.is_none() && address_query.avail_address.is_none() {
        tracing::error!("Query params not provided.");
        return Err(ErrorResponse::with_status_and_headers(
            anyhow!("Invalid request: Query params not provided"),
            StatusCode::BAD_REQUEST,
            &[("Cache-Control", "max-age=60, must-revalidate")],
        ));
    }

    let cloned_state = state.clone();
    let mut conn = cloned_state
        .connection_pool
        .get_timeout(Duration::from_secs(1))
        .expect("Get connection pool");

    // Initialize the result variables
    let mut transaction_results: TransactionResult = TransactionResult::default();

    let mut eth_send_query = ethereum_sends.into_boxed();
    if let Some(eth_address) = address_query.eth_address {
        eth_send_query = eth_send_query
            .filter(schema::ethereum_sends::depositor_address.eq(format!("{:?}", eth_address)));
    }

    if let Some(avail_address) = address_query.avail_address {
        eth_send_query = eth_send_query
            .or_filter(schema::ethereum_sends::receiver_address.eq(format!("{:?}", avail_address)));
    }

    // Return the combined results
    let ethereum_sends_results = eth_send_query
        .select(EthereumSend::as_select())
        .order_by(schema::ethereum_sends::source_timestamp.desc())
        .limit(state.transactions_result_max_size.into())
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

    let mut avail_send_query = avail_sends.into_boxed();
    if let Some(avail_address) = address_query.avail_address {
        avail_send_query = avail_send_query
            .filter(schema::avail_sends::depositor_address.eq(format!("{:?}", avail_address)));
    }

    if let Some(eth_address) = address_query.eth_address {
        avail_send_query = avail_send_query
            .or_filter(schema::avail_sends::receiver_address.eq(format!("{:?}", eth_address)));
    }

    let avail_sends_results = avail_send_query
        .select(AvailSend::as_select())
        .order_by(schema::avail_sends::source_timestamp.desc())
        .limit(state.transactions_result_max_size.into())
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

    let avail_send_count = transaction_results.avail_send.len() as u32;
    let eth_send_count = transaction_results.eth_send.len() as u32;

    // if number of results is the same as the configure value
    if avail_send_count >= state.transactions_result_max_size
        || eth_send_count >= state.transactions_result_max_size
    {
        warn!(
            "Transaction result has more items that the configured {}",
            state.transactions_result_max_size
        );
    }

    Ok((
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
        .into_response())
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
    let data_proof_res: KateQueryDataProofResponse = data_proof
        .map_err(|e| {
            tracing::error!("❌ : {e:#}");
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?
        .map_err(|e| {
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::BAD_REQUEST,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

    let succinct_data = succinct_response
        .map_err(|e| {
            tracing::error!("❌ : {e:#}");
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?
        .map_err(|e| {
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;
    let succinct_data = match succinct_data {
        SuccinctAPIResponse {
            data: Some(data), ..
        } => data,
        SuccinctAPIResponse {
            success: Some(false),
            error: Some(data),
            ..
        } => {
            if data.contains("not in the range of blocks") {
                tracing::warn!(
                    "⏳ Succinct VectorX contract not updated yet! Response: {}",
                    data
                );
            } else {
                tracing::error!(
                    "❌ Succinct API returned unsuccessfully. Response: {}",
                    data
                );
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
            tracing::error!("❌ Succinct API returned no data");
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("Succinct API returned no data"),
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

/// Creates a request to the beaconcha service for mapping slot to the block number.
#[inline(always)]
async fn get_beacon_slot(
    Path(slot): Path<U256>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let resp = state
        .request_client
        .get(format!(
            "{}/eth/v2/beacon/blocks/{}",
            state.beaconchain_base_url, slot
        ))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("❌ Cannot get beacon API data: {e:#}");
            ErrorResponse::with_status_and_headers(
                e.into(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

    let response_data = resp.json::<Root>().await.map_err(|e| {
        tracing::error!("❌ Cannot get beacon API response data: {e:#}");
        ErrorResponse::with_status_and_headers(
            e.into(),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "public, max-age=60, must-revalidate")],
        )
    })?;
    Ok((
        StatusCode::OK,
        [(
            "Cache-Control",
            format!(
                "public, max-age={}, immutable",
                state.slot_mapping_cache_maxage
            ),
        )],
        Json(json!(SlotMappingResponse {
            block_number: response_data
                .data
                .message
                .body
                .execution_payload
                .block_number,
            block_hash: response_data.data.message.body.execution_payload.block_hash
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

/// get_eth_head returns Ethereum head with the latest slot/block that is stored and a time.
#[inline(always)]
async fn get_eth_head_legacy(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let slot_block_head = SLOT_BLOCK_HEAD.read().await;
    let (slot, _block, _hash, timestamp) = slot_block_head.as_ref().ok_or_else(|| {
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
        Json(json!(HeadResponseLegacy {
            slot: *slot,
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
        state.succinct_base_url, "range", state.contract_chain_id, state.contract_address
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
        Ok(SuccinctAPIResponse {
            data: Some(data), ..
        }) => data,
        Ok(SuccinctAPIResponse {
            success: Some(false),
            error: Some(data),
            ..
        }) => {
            if data.contains("not in the range of blocks") {
                tracing::warn!(
                    "Succinct VectorX contract not updated yet! Response: {}",
                    data
                );
            } else {
                tracing::error!("Succinct API returned unsuccessfully. Response: {}", data);
            }
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("error: {data}"),
                StatusCode::NOT_FOUND,
                &[("Cache-Control", "public, max-age=60, immutable")],
            ));
        }
        Err(err) => {
            tracing::error!("Cannot get succinct api response {:?}", err);
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("error: {err}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "max-age=60, must-revalidate")],
            ));
        }
        _ => {
            tracing::error!("Succinct API returned no data");
            return Err(ErrorResponse::with_status_and_headers(
                anyhow!("Succinct API returned no data"),
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
) -> JoinHandle<Result<SuccinctAPIResponse, reqwest::Error>> {
    let url = format!(
        "{}?chainName={}&contractChainId={}&contractAddress={}&blockHash={}",
        state.succinct_base_url,
        state.avail_chain_name,
        state.contract_chain_id,
        state.contract_address,
        block_hash
    );
    tokio::spawn(async move {
        let res = state.request_client.get(url).send().await;
        match res {
            Ok(resp) => resp.json::<SuccinctAPIResponse>().await,
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
        env::var("PG_USERNAME").unwrap_or("myuser".to_owned()),
        env::var("PG_PASSWORD").unwrap_or("mypassword".to_owned()),
        env::var("POSTGRES_URL").unwrap_or("localhost:5432".to_owned()),
        env::var("POSTGRES_DB").unwrap_or("bridge-ui-indexer".to_owned()),
    );
    let connection_pool = r2d2::Pool::builder()
        .build(ConnectionManager::<PgConnection>::new(connections_string))
        .expect("Failed to create pool.");
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
        connection_pool,
        transactions_result_max_size: env::var("TRANSACTIONS_RESULT_MAX_SIZE")
            .ok()
            .and_then(|transactions_mapping_response| {
                transactions_mapping_response.parse::<u32>().ok()
            })
            .unwrap_or(500),
        chains,
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/versions", get(versions))
        .route("/v1/info", get(info))
        .route("/info", get(info))
        .route("/v1/eth/proof/{block_hash}", get(get_eth_proof))
        .route("/eth/proof/{block_hash}", get(get_eth_proof))
        .route("/v1/eth/head", get(get_eth_head))
        .route("/eth/head", get(get_eth_head_legacy))
        .route("/v1/avl/head", get(get_avl_head))
        .route("/avl/head", get(get_avl_head))
        .route(
            "/v1/avl/proof/{block_hash}/{message_id}",
            get(get_avl_proof),
        )
        .route("/v1/transactions", get(transactions))
        .route("/transactions", get(transactions))
        .route("/avl/proof/{block_hash}/{message_id}", get(get_avl_proof))
        .route("/beacon/slot/{slot_number}", get(get_beacon_slot))
        .route("/v1/head/{chain_id}", get(get_head))
        .route("/v1/proof/{chain_id}", get(get_proof))
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
