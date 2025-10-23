use crate::schema::sql_types::Status;
use alloy::primitives::{Address, B256};
use alloy::sol;
use avail_core::data_proof::AddressedMessage;
use axum::Json;
use axum::response::{IntoResponse, Response};
use chrono::NaiveDateTime;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{IsNull, Output};
use diesel::{
    deserialize::{self, FromSql},
    expression::AsExpression,
    serialize::ToSql,
    *,
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use jsonrpsee::core::Serialize;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use serde_with::serde_as;
use std::io::Write;

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotMappingResponse {
    pub block_hash: String,
    pub block_number: String,
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
struct RangeBlocks {
    start: u32,
    end: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeBlocksAPIResponse {
    data: RangeBlocks,
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

#[derive(Debug, Clone, PartialEq, FromSqlRow, AsExpression, Eq)]
#[diesel(sql_type = Status)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusEnum {
    InProgress,
    ClaimPending,
    Bridged,
}
impl ToSql<Status, Pg> for StatusEnum {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        match *self {
            StatusEnum::InProgress => out.write_all(b"IN_PROGRESS")?,
            StatusEnum::ClaimPending => out.write_all(b"CLAIM_PENDING")?,
            StatusEnum::Bridged => out.write_all(b"BRIDGED")?,
        }
        Ok(IsNull::No)
    }
}

impl FromSql<Status, Pg> for StatusEnum {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"IN_PROGRESS" => Ok(StatusEnum::InProgress),
            b"CLAIM_PENDING" => Ok(StatusEnum::ClaimPending),
            b"BRIDGED" => Ok(StatusEnum::Bridged),
            _ => Err(format!(
                "Unrecognized enum variant {}",
                std::str::from_utf8(bytes.as_bytes()).unwrap()
            )
            .as_str()
            .into()),
        }
    }
}

#[derive(Queryable, Selectable, Insertable, Identifiable, Serialize)]
#[serde(rename_all = "camelCase")]
#[diesel(table_name = crate::schema::avail_sends)]
#[diesel(primary_key(message_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[derive(Clone, Debug)]
#[serde_as]
pub struct AvailSend {
    pub message_id: i64,
    pub status: StatusEnum,
    pub source_transaction_hash: String,
    pub source_block_number: i64,
    pub source_block_hash: String,
    pub source_transaction_index: i64,
    #[serde_as(as = "TimestampSeconds")]
    pub source_timestamp: NaiveDateTime,
    pub token_id: String,
    pub destination_block_number: Option<i64>,
    pub destination_block_hash: Option<String>,
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub destination_timestamp: Option<NaiveDateTime>,
    pub depositor_address: String,
    pub receiver_address: String,
    pub amount: String,
}

#[derive(Queryable, Selectable, Insertable, Identifiable, Serialize)]
#[serde(rename_all = "camelCase")]
#[diesel(table_name = crate::schema::ethereum_sends)]
#[diesel(primary_key(message_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[derive(Clone, Debug)]
#[serde_as]
pub struct EthereumSend {
    pub message_id: i64,
    pub status: StatusEnum,
    pub source_transaction_hash: String,
    pub source_block_number: i64,
    pub source_block_hash: String,
    #[serde_as(as = "TimestampSeconds")]
    pub source_timestamp: NaiveDateTime,
    pub token_id: String,
    pub destination_block_number: Option<i64>,
    pub destination_block_hash: Option<String>,
    pub destination_transaction_index: Option<i64>,
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub destination_timestamp: Option<NaiveDateTime>,
    pub depositor_address: String,
    pub receiver_address: String,
    pub amount: String,
}
