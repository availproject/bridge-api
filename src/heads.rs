use crate::beacon::{ExecutionBlock, Root};
use crate::contracts::SP1Vector;
use crate::error::{ErrorResponse, UpstreamError};
#[cfg(test)]
use crate::state::test_state;
use crate::state::{AppState, SLOT_BLOCK_HEAD};

use alloy::primitives::{B256, hex};
use anyhow::{Context, Result, anyhow};
#[cfg(test)]
use axum::body::to_bytes;
#[cfg(test)]
use axum::response::Response;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use backon::ExponentialBuilder;
use backon::Retryable;
use chrono::Utc;
use jsonrpsee::{core::client::ClientT, rpc_params};
use serde::{Deserialize, Deserializer, Serialize};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use sp_core::Decode;
use sp_io::hashing::twox_128;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// get_eth_head returns Ethereum head with the latest slot/block that is stored and a time.
#[inline(always)]
pub(crate) async fn get_eth_head(
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
            timestamp_diff: now.saturating_sub(*timestamp)
        })),
    )
        .into_response())
}

/// get_avl_head returns start and end blocks which the contract has commitments
#[inline(always)]
pub(crate) async fn get_avl_head(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let url = format!(
        "{}/{}?contractChainId={}&contractAddress={}",
        state.merkle_proof_service_base_url,
        "range",
        state.contract_chain_id,
        state.contract_address
    );
    let response = state.request_client.get(url).send().await.map_err(|_| {
        let e = UpstreamError::MerkleProofService;
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
        .map_err(|_| {
            let e = UpstreamError::MerkleProofService;
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
pub(crate) async fn get_head(
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

    let contract = SP1Vector::new(chain.contract_address, chain.provider.clone());
    let head = contract.latestBlock().call().await.map_err(|_| {
        let e = UpstreamError::Rpc;
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

pub(crate) async fn track_slot_avail_task(state: Arc<AppState>) -> Result<()> {
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

                let response = state
                    .request_client
                    .get(format!(
                        "{}/eth/v2/beacon/blocks/{}",
                        state.beaconchain_base_url, slot
                    ))
                    .send()
                    .await
                    .map_err(|_| UpstreamError::Beacon)
                    .context("Cannot get beacon block")?;
                let root = response
                    .json::<Root>()
                    .await
                    .context("Cannot decode beacon response")?;
                let (bl, hash) = match root.data.message.body.execution_block()? {
                    ExecutionBlock::Known { number, hash } => (number, hash),
                    ExecutionBlock::ByHash(hash) => {
                        let header: Option<HeaderBlockNumber> = state
                            .ethereum_client
                            .request("eth_getBlockByHash", rpc_params![hash, false])
                            .await
                            .context("Cannot get execution block")?;
                        let header =
                            header.with_context(|| format!("Execution block {hash} not found"))?;
                        (header.number as u64, hash)
                    }
                };
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

#[cfg(test)]
async fn error_body(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body = to_bytes(response.into_body(), 2048).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn test_head_error_when_rpc_is_unreachable() {
    let response = get_head(Path(1), State(test_state())).await.into_response();
    let (status, body) = error_body(response).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, r#"{"error":"chain RPC request failed"}"#);
}

#[tokio::test]
async fn test_avl_head_error_when_merkle_proof_service_is_unreachable() {
    let response = get_avl_head(State(test_state())).await.into_response();
    let (status, body) = error_body(response).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, r#"{"error":"merkle proof service request failed"}"#);
}

#[tokio::test]
async fn test_eth_head_with_timestamp_ahead_of_clock() {
    let timestamp = Utc::now().timestamp() as u64 + 60;
    *SLOT_BLOCK_HEAD.write().await = Some((1, 1, B256::ZERO, timestamp));

    let response = get_eth_head(State(test_state())).await.into_response();
    let body = to_bytes(response.into_body(), 2048).await.unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["timestampDiff"], 0);
}
