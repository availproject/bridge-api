use self::TxDirection::{AvailEth, EthAvail};
use crate::error::{ErrorResponse, UpstreamError};
#[cfg(test)]
use crate::heads::error_body;
use crate::heads::{HeaderBlockNumber, RangeBlocksAPIResponse};
#[cfg(test)]
use crate::state::test_state;
use crate::state::{AppState, SLOT_BLOCK_HEAD};

use anyhow::anyhow;
use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use jsonrpsee::{core::ClientError, core::client::ClientT, rpc_params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::serde_as;
use sp_core::H160;
use sqlx::FromRow;
#[cfg(test)]
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;

#[inline(always)]
pub(crate) async fn transactions(
    Query(address_query): Query<TransactionQueryParams>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    // check provided params
    if address_query.eth_address.is_none() && address_query.avail_address.is_none() {
        tracing::error!("Query params not provided.");
        return Err(ErrorResponse::with_status_and_headers(
            anyhow!("Invalid request: Query params not provided"),
            StatusCode::BAD_REQUEST,
            &[("Cache-Control", "max-age=60, must-revalidate")],
        ));
    }

    let mut transaction_data_results: Vec<TransactionData> = vec![];

    if let Some(eth_address) = address_query.eth_address {
        let transactions: Vec<EthTransactionRow> = sqlx::query_file_as!(
            EthTransactionRow,
            "sql/query_eth_tx.sql",
            format!("{:?}", eth_address),
            "MessageSent",
            true
        )
        .fetch_all(&state.db)
        .await
        .map_err(database_error)?;

        let slot_block_head = SLOT_BLOCK_HEAD.read().await;
        let (_slot, last_eth_block, _hash, helios_update_timestamp) =
            slot_block_head.as_ref().ok_or_else(|| {
                ErrorResponse::with_status(anyhow!("Not found"), StatusCode::INTERNAL_SERVER_ERROR)
            })?;

        let claim_estimate =
            time_until_next_helios_update(*helios_update_timestamp, state.helios_update_frequency);

        for mut tx in transactions {
            let mut estimate = None;
            if tx.final_status != BridgeStatusEnum::Bridged
                && tx.source_block_height <= (*last_eth_block) as i32
            {
                // safe cast
                tx.final_status = BridgeStatusEnum::ClaimReady
            }
            if tx.final_status != BridgeStatusEnum::Bridged
                && tx.final_status != BridgeStatusEnum::ClaimReady
            {
                estimate = Some(claim_estimate.as_secs());
            }

            transaction_data_results.push(TransactionData::new(
                EthAvail,
                tx.message_id,
                tx.sender,
                tx.receiver,
                tx.source_block_hash,
                tx.source_transaction_hash,
                tx.amount,
                tx.final_status,
                tx.timestamp,
                estimate,
                Some(tx.source_block_height),
                None,
                tx.destination_block_height,
                tx.destination_tx_index,
                None,
            ));
        }
    }

    if let Some(avail_address) = address_query.avail_address {
        let transactions: Vec<AvailTransactionRow> = sqlx::query_file_as!(
            AvailTransactionRow,
            "sql/query_avail_tx.sql",
            avail_address,
            "FungibleToken",
            "MessageReceived",
            true
        )
        .fetch_all(&state.db)
        .await
        .map_err(database_error)?;

        // If the range or the header request fails, the rows keep their DB status and get no estimate.
        let range_end = fetch_range_blocks(&state)
            .await
            .ok()
            .map(|range_blocks| range_blocks.data.end);

        let header: Result<HeaderBlockNumber, ClientError> = state
            .avail_client
            .request("chain_getHeader", rpc_params![])
            .await;
        let latest_block_number = header
            .inspect_err(|e| tracing::error!("❌ Cannot get Avail header: {e:#}"))
            .ok()
            .map(|header| header.number);

        let claim_estimate = match (range_end, latest_block_number) {
            (Some(range_end), Some(latest_block_number)) => {
                tracing::info!(
                    latest_block_number = latest_block_number,
                    range_end = range_end,
                    blocks_since = latest_block_number.saturating_sub(range_end),
                    "time_until_next_vector_update"
                );
                Some(time_until_next_vector_update(
                    latest_block_number,
                    range_end,
                    state.vector_update_frequency,
                    20,
                ))
            }
            _ => None,
        };

        for mut tx in transactions {
            let mut estimate = None;

            if tx.final_status == BridgeStatusEnum::InProgress
                && range_end.is_some_and(|range_end| tx.source_block_height <= range_end as i32)
            {
                tx.final_status = BridgeStatusEnum::ClaimReady;
            }
            if tx.final_status == BridgeStatusEnum::Initiated
                || tx.final_status == BridgeStatusEnum::InProgress
            {
                estimate = claim_estimate.map(|claim_estimate| claim_estimate.as_secs());
            }

            transaction_data_results.push(TransactionData::new(
                AvailEth,
                tx.message_id,
                tx.sender.unwrap_or("".to_string()), // cannot be empty because of where clause
                tx.receiver,
                tx.source_block_hash,
                tx.source_transaction_hash,
                tx.amount,
                tx.final_status,
                tx.block_timestamp,
                estimate,
                Some(tx.source_block_height),
                Some(tx.source_tx_index),
                None,
                None,
                tx.destination_tx_hash,
            ));
        }
    }

    transaction_data_results.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));

    Ok((
        StatusCode::OK,
        [("Cache-Control", "max-age=10, must-revalidate")],
        Json(json!(transaction_data_results)),
    )
        .into_response())
}

/// Logs a failed query and answers with a fixed text, so the client does not see the sqlx text.
fn database_error(e: sqlx::Error) -> ErrorResponse {
    tracing::error!("❌ Cannot fetch transactions: {e:#}");
    ErrorResponse::with_status(
        anyhow!(UpstreamError::Database),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

async fn fetch_range_blocks(
    state: &Arc<AppState>,
) -> Result<RangeBlocksAPIResponse, ErrorResponse> {
    let block_range_url = format!(
        "{}/{}?chainName={}&contractChainId={}&contractAddress={}",
        state.merkle_proof_service_base_url,
        "range",
        state.avail_chain_name,
        state.contract_chain_id,
        state.contract_address
    );

    let response = state
        .request_client
        .get(block_range_url)
        .send()
        .await
        .map_err(|_| {
            let e = UpstreamError::MerkleProofService;
            tracing::error!("Cannot parse range blocks: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow!("{e:#}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;

    let range_blocks = response
        .json::<RangeBlocksAPIResponse>()
        .await
        .map_err(|_| {
            let e = UpstreamError::MerkleProofService;
            tracing::error!("Cannot parse range blocks: {e:#}");
            ErrorResponse::with_status_and_headers(
                anyhow!("{e:#}"),
                StatusCode::INTERNAL_SERVER_ERROR,
                &[("Cache-Control", "public, max-age=60, must-revalidate")],
            )
        })?;
    Ok(range_blocks)
}

fn time_until_next_vector_update(
    current_block: u32,
    last_updated_block: u32,
    blocks_per_update: u32,
    block_time_seconds: u32,
) -> Duration {
    let blocks_since_update = current_block.saturating_sub(last_updated_block);
    let blocks_remaining = blocks_per_update.saturating_sub(blocks_since_update);

    Duration::from_secs((blocks_remaining * block_time_seconds) as u64)
}

fn time_until_next_helios_update(timestamp: u64, helios_update_frequency: u32) -> Duration {
    let now = Utc::now().timestamp() as u64;
    let time_since_update = now.saturating_sub(timestamp);
    let update_frequency = Duration::from_secs(helios_update_frequency as u64).as_secs();
    let remaining = update_frequency.saturating_sub(time_since_update);
    Duration::from_secs(remaining)
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
pub struct EthTransactionRow {
    pub message_id: BigDecimal,
    pub sender: String,
    pub receiver: String,
    pub source_block_hash: String,
    pub source_transaction_hash: String,
    pub amount: String,
    pub timestamp: i64,
    pub final_status: BridgeStatusEnum,
    pub source_block_height: i32,
    pub destination_block_height: Option<i32>,
    pub destination_tx_index: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
#[serde_as]
#[serde(rename_all = "camelCase")]
pub struct AvailTransactionRow {
    pub message_id: BigDecimal,
    pub sender: Option<String>,
    pub receiver: String,
    pub source_block_hash: String,
    pub source_transaction_hash: String,
    pub amount: String,
    pub block_timestamp: i64,
    pub final_status: BridgeStatusEnum,
    pub source_block_height: i32,
    pub source_tx_index: i32,
    pub destination_tx_hash: Option<String>,
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
    pub message_id: BigDecimal,
    pub sender: String,
    pub receiver: String,
    pub source_block_hash: String,
    pub source_tx_hash: String,
    pub amount: String,
    pub status: BridgeStatusEnum,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_estimate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_block_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_tx_index: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_block_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_tx_index: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_tx_hash: Option<String>,
}

impl TransactionData {
    pub fn new(
        direction: TxDirection,
        message_id: BigDecimal,
        sender: String,
        receiver: String,
        source_block_hash: String,
        source_tx_hash: String,
        amount: String,
        status: BridgeStatusEnum,
        timestamp: i64,
        claim_estimate: Option<u64>,
        source_block_number: Option<i32>,
        source_tx_index: Option<i32>,
        destination_block_number: Option<i32>,
        destination_tx_index: Option<i32>,
        destination_tx_hash: Option<String>,
    ) -> Self {
        Self {
            direction,
            message_id,
            sender,
            receiver,
            source_block_hash,
            source_tx_hash,
            amount,
            status,
            timestamp,
            claim_estimate,
            source_block_number,
            source_tx_index,
            destination_block_number,
            destination_tx_index,
            destination_tx_hash,
        }
    }
}

#[cfg(test)]
fn state_without_database() -> Arc<AppState> {
    let mut state = Arc::into_inner(test_state()).unwrap();
    // Nothing listens here. The short timeout stops the pool from retrying for 30 seconds.
    state.db = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgresql://avail:avail@127.0.0.1:1/ui-indexer")
        .unwrap();
    Arc::new(state)
}

/// Collects the log lines of one test.
#[cfg(test)]
#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// One test checks the body and the log line. tracing caches, per log call site, whether a
// subscriber wants the event. A second test that reaches `database_error` on a thread without a
// subscriber can cache "no" first, and then this test's subscriber gets nothing.
#[tokio::test]
async fn test_transactions_database_error_is_logged_and_gets_a_fixed_body() {
    let log = LogBuffer::default();
    let writer = log.clone();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    );

    let mut answers = vec![];
    for query in [
        TransactionQueryParams {
            eth_address: Some(H160::zero()),
            avail_address: None,
        },
        TransactionQueryParams {
            eth_address: None,
            avail_address: Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_owned()),
        },
    ] {
        let response = transactions(Query(query), State(state_without_database()))
            .await
            .into_response();
        answers.push(error_body(response).await);
    }

    let fixed_text = (
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":"database request failed"}"#.to_owned(),
    );
    assert_eq!(answers, [fixed_text.clone(), fixed_text]);

    // One line for each of the two queries.
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        log.matches("Cannot fetch transactions: pool timed out")
            .count(),
        2,
        "{log}"
    );
}

#[test]
fn test_remaining_time_for_vector_update() {
    let duration = time_until_next_vector_update(350, 50, 360, 20);
    assert_eq!(1200, duration.as_secs());
    let duration = time_until_next_vector_update(100, 50, 360, 20);
    assert_eq!(6200, duration.as_secs());
}

#[test]
fn test_remaining_time_for_helios_update() {
    let update = Utc::now().timestamp() - 1200;
    let remaining = time_until_next_helios_update(update as u64, 3600);
    // The clock can tick between the two reads.
    assert!((2399..=2400).contains(&remaining.as_secs()));
}

#[test]
fn test_remaining_time_for_helios_update_with_timestamp_ahead_of_clock() {
    // The Avail block time can be ahead of this server's clock.
    let update = Utc::now().timestamp() + 60;
    let remaining = time_until_next_helios_update(update as u64, 3600);
    assert_eq!(3600, remaining.as_secs());
}
