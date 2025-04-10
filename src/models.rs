use crate::schema::sql_types::Status;
use alloy_primitives::B256;
use avail_core::data_proof::AddressedMessage;
use chrono::NaiveDateTime;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{IsNull, Output};
use diesel::{
    deserialize::{self, FromSql},
    expression::AsExpression,
    serialize::ToSql,
    *,
};
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use serde_with::serde_as;
use std::io::Write;

#[derive(Deserialize)]
pub struct IndexStruct {
    pub index: u32,
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
pub struct SuccinctAPIResponse {
    pub data: Option<SuccinctAPIData>,
    pub error: Option<String>,
    pub success: Option<bool>,
}

#[derive(Deserialize)]
pub struct BeaconAPIResponse {
    pub status: String,
    pub data: BeaconAPIResponseData,
}

#[derive(Deserialize, Serialize)]
pub struct BeaconAPIResponseData {
    pub blockroot: B256,
    pub exec_block_number: u32,
    pub epoch: u32,
    pub slot: u32,
    pub exec_state_root: B256,
    pub exec_block_hash: B256,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotMappingResponse {
    pub block_hash: B256,
    pub block_number: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccinctAPIData {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadResponseLegacy {
    pub slot: u64,
    pub timestamp: u64,
    pub timestamp_diff: u64,
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
