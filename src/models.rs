use crate::schema::sql_types::{ClaimType, Status};
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

#[derive(Debug, Clone, PartialEq, FromSqlRow, AsExpression, Eq)]
#[diesel(sql_type = ClaimType)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClaimTypeEnum {
    Auto,
    Manual,
}

impl ToSql<ClaimType, Pg> for ClaimTypeEnum {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        match *self {
            ClaimTypeEnum::Auto => out.write_all(b"AUTO")?,
            ClaimTypeEnum::Manual => out.write_all(b"MANUAL")?,
        }
        Ok(IsNull::No)
    }
}

impl FromSql<ClaimType, Pg> for ClaimTypeEnum {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"AUTO" => Ok(ClaimTypeEnum::Auto),
            b"MANUAL" => Ok(ClaimTypeEnum::Manual),
            _ => Err("Unrecognized enum variant".into()),
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
    pub claim_type: ClaimTypeEnum,
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
    pub claim_type: ClaimTypeEnum,
}
