use alloy::primitives::{Address, B256};
use alloy::sol;
use avail_core::data_proof::AddressedMessage;
use axum::Json;
use axum::response::{IntoResponse, Response};

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use jsonrpsee::core::Serialize;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use serde_with::serde_as;
use sp_core::H160;
use sqlx::FromRow;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1Vector,
    "src/abi/SP1Vector.json"
);

#[derive(Debug, Deserialize)]
pub struct Root {
    pub data: Data,
}

#[derive(Debug, Deserialize)]
pub struct Data {
    pub message: Message,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub slot: String,
    pub body: MessageBody,
}

#[derive(Debug, Deserialize)]
pub struct MessageBody {
    pub execution_payload: ExecutionPayload,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionPayload {
    pub block_number: String,
    pub block_hash: String,
}

pub struct ErrorResponse {
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
pub struct Chain {
    pub rpc_url: String,
    pub contract_address: Address,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadResponseV2 {
    pub slot: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub timestamp: u64,
    pub timestamp_diff: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ChainHeadResponse {
    pub head: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeBlocks {
    pub start: u32,
    pub end: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeBlocksAPIResponse {
    pub data: RangeBlocks,
}

#[derive(Debug, Deserialize)]
pub struct HeaderBlockNumber {
    #[serde(deserialize_with = "hex_to_u32")]
    pub number: u32,
}

fn hex_to_u32<'de, D>(deserializer: D) -> anyhow::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;
    u32::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
}

#[derive(Debug, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "status")]
pub enum BridgeStatusEnum {
    #[sqlx(rename = "initiated")]
    Initiated,
    #[sqlx(rename = "in_progress")]
    InProgress,
    #[sqlx(rename = "claim_ready")]
    ClaimReady,
    #[sqlx(rename = "bridged")]
    Bridged,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionQueryParams {
    pub eth_address: Option<H160>,
    pub avail_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
#[serde_as]
#[serde(rename_all = "camelCase")]
pub struct TransactionRow {
    pub message_id: i64,
    pub sender: String,
    pub receiver: String,
    pub source_block_hash: String,
    pub source_transaction_hash: String,
    pub amount: String,
    pub final_status: BridgeStatusEnum,
    pub block_height: i32,
    pub ext_index: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TxDirection {
    AvailEth,
    EthAvail,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde_as]
#[serde(rename_all = "camelCase")]
pub struct TransactionData {
    pub direction: TxDirection,
    pub message_id: i64,
    pub sender: String,
    pub receiver: String,
    pub source_block_hash: String,
    pub source_transaction_hash: String,
    pub amount: String,
    pub status: BridgeStatusEnum,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_estimate: Option<u64>,
    pub destination_block_number: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<i32>,
}

impl TransactionData {
    pub fn new(
        direction: TxDirection,
        message_id: i64,
        sender: String,
        receiver: String,
        source_block_hash: String,
        source_transaction_hash: String,
        amount: String,
        status: BridgeStatusEnum,
        claim_estimate: Option<u64>,
        destination_block_number: i32,
        tx_index: Option<i32>,
    ) -> Self {
        Self {
            direction,
            message_id,
            sender,
            receiver,
            source_block_hash,
            source_transaction_hash,
            amount,
            status,
            claim_estimate,
            destination_block_number,
            tx_index,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionRpc {
    pub from: String,
    pub to: String,
    pub input: String,
    pub value: String,
    #[serde(deserialize_with = "hex_to_u32")]
    pub nonce: u32,
    pub block_hash: String,
    #[serde(deserialize_with = "hex_to_u32")]
    pub block_number: u32,
    #[serde(deserialize_with = "hex_to_u32")]
    pub transaction_index: u32,
    pub hash: String,
}
