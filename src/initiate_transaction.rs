use crate::AppState;
use crate::models::{ErrorResponse, InitiateRequest};
use alloy::primitives::{U256, hex};
use alloy::signers::k256::sha2::Digest;
use alloy::sol_types::SolCall;
use anyhow::anyhow;
use avail_core::data_proof::Message;
use axum::response::Response;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use parity_scale_codec::{Compact, Decode};
use serde_json::{Value, json};
use sha3::Keccak256;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::{blake2_256, twox_128};
use std::sync::Arc;
pub(crate) async fn initiate_transaction(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitiateRequest>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let has_eth = request.eth_tx_hash.is_some();
    let has_avail = request.avail_block_number.is_some() || request.avail_tx_index.is_some();

    if !has_eth && !has_avail {
        return Err(ErrorResponse::with_status(
            anyhow!("Either ethTxHash or (availBlockNumber and availTxIndex) must be provided"),
            StatusCode::BAD_REQUEST,
        ));
    }
    if has_eth && has_avail {
        return Err(ErrorResponse::with_status(
            anyhow!("Provide either ethTxHash or (availBlockNumber and availTxIndex), not both"),
            StatusCode::BAD_REQUEST,
        ));
    }
    if has_avail && (request.avail_block_number.is_none() || request.avail_tx_index.is_none()) {
        return Err(ErrorResponse::with_status(
            anyhow!("Both availBlockNumber and availTxIndex must be provided"),
            StatusCode::BAD_REQUEST,
        ));
    }

    if let Some(ref hash) = request.eth_tx_hash {
        if hash.len() != 66 || !hash.starts_with("0x") || hex::decode(&hash[2..]).is_err() {
            return Err(ErrorResponse::with_status(
                anyhow!("Invalid transaction hash format, expected 0x-prefixed 32-byte hex"),
                StatusCode::BAD_REQUEST,
            ));
        }
    }
    if let Some(message_id) = request.message_id.as_deref() {
        validate_message_id(message_id)?;
    }

    // Check if already processed to avoid redundant RPC calls (skip for claims)
    if request.message_id.is_none() {
        if let Some(eth_tx_hash) = &request.eth_tx_hash {
            let exists: Option<bool> =
                sqlx::query_file_scalar!("sql/check_initiated_tx_by_hash.sql", eth_tx_hash)
                    .fetch_one(&state.db)
                    .await?;
            if exists.unwrap_or(false) {
                return Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response());
            }
        }
        if let (Some(bn), Some(ti)) = (request.avail_block_number, request.avail_tx_index) {
            let exists: Option<bool> = sqlx::query_file_scalar!(
                "sql/check_initiated_tx_by_block.sql",
                bn as i32,
                ti as i32
            )
            .fetch_one(&state.db)
            .await?;
            if exists.unwrap_or(false) {
                return Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response());
            }
        }
    }

    match (
        &request.message_id,
        &request.eth_tx_hash,
        request.avail_block_number.zip(request.avail_tx_index),
    ) {
        (Some(message_id), Some(eth_tx_hash), _) => {
            claim_eth_transaction(&state, eth_tx_hash, message_id).await
        }
        (Some(message_id), None, Some((block_number, tx_index))) => {
            claim_avail_transaction(&state, block_number, tx_index, message_id).await
        }
        (None, Some(eth_tx_hash), _) => initiate_eth_transaction(&state, eth_tx_hash).await,
        (None, None, Some((block_number, tx_index))) => {
            initiate_avail_transaction(&state, block_number, tx_index).await
        }
        _ => Err(ErrorResponse::with_status(
            anyhow!("Wrong input"),
            StatusCode::BAD_REQUEST,
        )),
    }
}

async fn initiate_eth_transaction(
    state: &Arc<AppState>,
    eth_tx_hash: &str,
) -> anyhow::Result<Response, ErrorResponse> {
    let receipt: Value = state
        .ethereum_client
        .request("eth_getTransactionReceipt", rpc_params![eth_tx_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch ETH receipt: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch transaction receipt"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    if receipt.is_null() {
        return Err(ErrorResponse::with_status(
            anyhow!("Transaction not found"),
            StatusCode::NOT_FOUND,
        ));
    }

    let tx: Value = state
        .ethereum_client
        .request("eth_getTransactionByHash", rpc_params![eth_tx_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch ETH transaction: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch transaction"),
                StatusCode::BAD_REQUEST,
            )
        })?;

    let block_hash = receipt["blockHash"]
        .as_str()
        .ok_or_else(|| {
            ErrorResponse::with_status(anyhow!("Missing blockHash"), StatusCode::BAD_REQUEST)
        })?
        .to_string();
    let block_number_hex = receipt["blockNumber"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing blockNumber"), StatusCode::BAD_REQUEST)
    })?;
    let block_number =
        i32::from_str_radix(block_number_hex.trim_start_matches("0x"), 16).map_err(|_| {
            ErrorResponse::with_status(anyhow!("Invalid blockNumber"), StatusCode::BAD_REQUEST)
        })?;

    // Find MessageSent event in logs
    let mut hasher = Keccak256::new();
    hasher.update(b"MessageSent(address,bytes32,uint256)");
    let event_topic = format!("0x{}", hex::encode(hasher.finalize()));

    let logs = receipt["logs"].as_array().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing logs"), StatusCode::BAD_REQUEST)
    })?;

    let event_log = logs
        .iter()
        .find(|log| log["topics"][0].as_str() == Some(&event_topic))
        .ok_or_else(|| {
            ErrorResponse::with_status(
                anyhow!("MessageSent event not found in transaction"),
                StatusCode::BAD_REQUEST,
            )
        })?;

    // sender from topic[1] (address left-padded to 32 bytes)
    let sender_topic = event_log["topics"][1].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing sender topic"), StatusCode::BAD_REQUEST)
    })?;

    let sender = format!("0x{}", &sender_topic[26..]);

    // receiver from topic[2] (bytes32)
    let receiver = event_log["topics"][2]
        .as_str()
        .ok_or_else(|| {
            ErrorResponse::with_status(anyhow!("Missing receiver topic"), StatusCode::BAD_REQUEST)
        })?
        .to_string();

    // messageId from data
    let msg_data = event_log["data"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing event data"), StatusCode::BAD_REQUEST)
    })?;
    let message_id = msg_data
        .parse::<U256>()
        .map(|v| v.to_string())
        .map_err(|_| {
            ErrorResponse::with_status(anyhow!("Missing messageId"), StatusCode::BAD_REQUEST)
        })?;

    // amount from tx input: sendAVAIL(bytes32,uint256)
    let input = tx["input"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing input"), StatusCode::BAD_REQUEST)
    })?;
    let input_bytes = hex::decode(input.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(anyhow!("Invalid input hex"), StatusCode::BAD_REQUEST)
    })?;
    let call = crate::AvailBridge::sendAVAILCall::abi_decode(&input_bytes).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Transaction is not a sendAVAIL call"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    let amount = call.amount.to_string();

    // timestamp from block
    let block: Value = state
        .ethereum_client
        .request("eth_getBlockByNumber", rpc_params![block_number_hex, false])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch block: {e:#}");
            ErrorResponse::with_status(anyhow!("Failed to fetch block"), StatusCode::BAD_REQUEST)
        })?;
    let timestamp_hex = block["timestamp"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing timestamp"), StatusCode::BAD_REQUEST)
    })?;
    let timestamp =
        i64::from_str_radix(timestamp_hex.trim_start_matches("0x"), 16).map_err(|_| {
            ErrorResponse::with_status(anyhow!("Invalid timestamp"), StatusCode::BAD_REQUEST)
        })?;

    sqlx::query_file!(
        "sql/insert_initiated_tx.sql",
        eth_tx_hash,
        "EthAvail",
        &message_id,
        &sender,
        &receiver,
        &amount,
        &block_hash,
        block_number,
        None::<i32>,
        timestamp,
        "initiate",
    )
    .execute(&state.db)
    .await?;

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}

async fn fetch_avail_block_timestamp(
    client: &HttpClient,
    block_hash: &str,
) -> anyhow::Result<i64, ErrorResponse> {
    let key = format!(
        "0x{}{}",
        hex::encode(twox_128(b"Timestamp")),
        hex::encode(twox_128(b"Now"))
    );
    let storage_hex: String = client
        .request("state_getStorage", rpc_params![&key, block_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block timestamp: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch block timestamp"),
                StatusCode::BAD_GATEWAY,
            )
        })?;
    let bytes = hex::decode(storage_hex.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid timestamp encoding"),
            StatusCode::BAD_GATEWAY,
        )
    })?;
    let timestamp_bytes: [u8; 8] =
        bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                ErrorResponse::with_status(
                    anyhow!("Invalid timestamp length"),
                    StatusCode::BAD_GATEWAY,
                )
            })?;
    let timestamp_ms = u64::from_le_bytes(timestamp_bytes);
    Ok((timestamp_ms / 1000) as i64)
}

async fn initiate_avail_transaction(
    state: &Arc<AppState>,
    block_number: u32,
    tx_index: u32,
) -> anyhow::Result<Response, ErrorResponse> {
    let block_hash: String = state
        .avail_client
        .request("chain_getBlockHash", rpc_params![block_number])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block hash: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch block hash"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    // Fetch block to get the extrinsic and extract signer
    let block: Value = state
        .avail_client
        .request("chain_getBlock", rpc_params![&block_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block: {e:#}");
            ErrorResponse::with_status(anyhow!("Failed to fetch block"), StatusCode::BAD_GATEWAY)
        })?;

    let extrinsics = block["block"]["extrinsics"].as_array().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing extrinsics"), StatusCode::BAD_GATEWAY)
    })?;

    let ext_hex = extrinsics
        .get(tx_index as usize)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ErrorResponse::with_status(
                anyhow!("Extrinsic not found at index {tx_index}"),
                StatusCode::NOT_FOUND,
            )
        })?;

    let ext_bytes = hex::decode(ext_hex.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid extrinsic encoding"),
            StatusCode::BAD_GATEWAY,
        )
    })?;

    // Extrinsic hash matching indexer's ext.metadata.ext_hash
    let ext_hash_hex = format!("0x{}", hex::encode(blake2_256(&ext_bytes)));

    // Decode extrinsic using SCALE codec cursor
    let mut cursor = &ext_bytes[..];
    let decode_err = |e| {
        ErrorResponse::with_status(
            anyhow!("Failed to decode extrinsic: {e}"),
            StatusCode::BAD_GATEWAY,
        )
    };

    // Skip compact length prefix
    <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?;

    // Version byte (0x84 = V4 signed)
    let version = u8::decode(&mut cursor).map_err(decode_err)?;

    // Extract signer from signed extrinsic
    let sender = if version & 0x80 != 0 {
        // MultiAddress::Id = 0x00 + 32 bytes AccountId
        let addr_type = u8::decode(&mut cursor).map_err(decode_err)?;
        if addr_type != 0x00 {
            return Err(ErrorResponse::with_status(
                anyhow!("Unsupported address type"),
                StatusCode::BAD_GATEWAY,
            ));
        }
        let account = <[u8; 32]>::decode(&mut cursor).map_err(decode_err)?;
        let sender = AccountId32::new(account).to_ss58check();

        // Skip MultiSignature
        let sig_type = u8::decode(&mut cursor).map_err(decode_err)?;
        match sig_type {
            0x00 | 0x01 => {
                <[u8; 64]>::decode(&mut cursor).map_err(decode_err)?;
            }
            0x02 => {
                <[u8; 65]>::decode(&mut cursor).map_err(decode_err)?;
            }
            _ => {
                return Err(ErrorResponse::with_status(
                    anyhow!("Unknown signature type"),
                    StatusCode::BAD_GATEWAY,
                ));
            }
        };

        // Skip SignedExtras: Era + Nonce + Tip + AppId
        let era = u8::decode(&mut cursor).map_err(decode_err)?;
        if era != 0x00 {
            u8::decode(&mut cursor).map_err(decode_err)?; // mortal era second byte
        }
        <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?; // nonce
        <Compact<u128>>::decode(&mut cursor).map_err(decode_err)?; // tip
        <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?; // app_id

        sender
    } else {
        String::new()
    };

    // Skip pallet_id + call_id
    <[u8; 2]>::decode(&mut cursor).map_err(decode_err)?;

    // Decode SendMessage params: Message + to (H256)
    let message = Message::decode(&mut cursor).map_err(decode_err)?;
    let to = sp_core::H256::decode(&mut cursor).map_err(decode_err)?;

    let amount = match &message {
        Message::FungibleToken { amount, .. } => amount.to_string(),
        _ => "0".to_string(),
    };
    let receiver = format!("0x{}", hex::encode(to.as_bytes()));

    // ID matching indexer's (block_height << 32) | ext_index
    let message_id = ((block_number as u64) << 32 | tx_index as u64).to_string();
    let timestamp = fetch_avail_block_timestamp(&state.avail_client, &block_hash).await?;

    sqlx::query_file!(
        "sql/insert_initiated_tx.sql",
        &ext_hash_hex,
        "AvailEth",
        &message_id,
        &sender,
        &receiver,
        &amount,
        &block_hash,
        block_number as i32,
        tx_index as i32,
        timestamp,
        "initiate",
    )
    .execute(&state.db)
    .await?;

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}

async fn claim_eth_transaction(
    state: &Arc<AppState>,
    eth_tx_hash: &str,
    message_id: &str,
) -> anyhow::Result<Response, ErrorResponse> {
    let requested_message_id = validate_message_id(message_id)?;

    // Verify tx exists
    let receipt: Value = state
        .ethereum_client
        .request("eth_getTransactionReceipt", rpc_params![eth_tx_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch ETH receipt: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch transaction receipt"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    if receipt.is_null() {
        return Err(ErrorResponse::with_status(
            anyhow!("Transaction not found"),
            StatusCode::NOT_FOUND,
        ));
    }
    let receipt_message_id =
        extract_eth_claim_message_id(&receipt, state.bridge_contract_address.as_str())?;
    ensure_message_id_matches(requested_message_id, receipt_message_id)?;

    let block_hash = receipt["blockHash"]
        .as_str()
        .ok_or_else(|| {
            ErrorResponse::with_status(anyhow!("Missing blockHash"), StatusCode::BAD_REQUEST)
        })?
        .to_string();
    let block_number_hex = receipt["blockNumber"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing blockNumber"), StatusCode::BAD_REQUEST)
    })?;
    let block_number =
        i32::from_str_radix(block_number_hex.trim_start_matches("0x"), 16).map_err(|_| {
            ErrorResponse::with_status(anyhow!("Invalid blockNumber"), StatusCode::BAD_REQUEST)
        })?;

    let tx: Value = state
        .ethereum_client
        .request("eth_getTransactionByHash", rpc_params![eth_tx_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch ETH transaction: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch transaction"),
                StatusCode::BAD_REQUEST,
            )
        })?;

    let sender = tx["from"].as_str().unwrap_or("").to_string();

    let block: Value = state
        .ethereum_client
        .request("eth_getBlockByNumber", rpc_params![block_number_hex, false])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch block: {e:#}");
            ErrorResponse::with_status(anyhow!("Failed to fetch block"), StatusCode::BAD_REQUEST)
        })?;
    let timestamp_hex = block["timestamp"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing timestamp"), StatusCode::BAD_REQUEST)
    })?;
    let timestamp =
        i64::from_str_radix(timestamp_hex.trim_start_matches("0x"), 16).map_err(|_| {
            ErrorResponse::with_status(anyhow!("Invalid timestamp"), StatusCode::BAD_REQUEST)
        })?;

    sqlx::query_file!(
        "sql/insert_initiated_tx.sql",
        eth_tx_hash,
        "AvailEth",
        message_id,
        &sender,
        "",
        "0",
        &block_hash,
        block_number,
        None::<i32>,
        timestamp,
        "claim",
    )
    .execute(&state.db)
    .await?;

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}

fn validate_message_id(message_id: &str) -> anyhow::Result<U256, ErrorResponse> {
    message_id.parse::<U256>().map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid messageId format, expected unsigned integer"),
            StatusCode::BAD_REQUEST,
        )
    })
}

fn ensure_message_id_matches(requested: U256, derived: U256) -> anyhow::Result<(), ErrorResponse> {
    if requested == derived {
        Ok(())
    } else {
        Err(ErrorResponse::with_status(
            anyhow!("Provided messageId does not match claim transaction"),
            StatusCode::BAD_REQUEST,
        ))
    }
}

fn extract_eth_claim_message_id(
    receipt: &Value,
    bridge_contract_address: &str,
) -> anyhow::Result<U256, ErrorResponse> {
    let logs = receipt["logs"].as_array().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing logs"), StatusCode::BAD_REQUEST)
    })?;

    let claim_log = logs
        .iter()
        .find(|log| {
            log["address"]
                .as_str()
                .map(|address| address.eq_ignore_ascii_case(bridge_contract_address))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            ErrorResponse::with_status(
                anyhow!("Claim event not found in transaction"),
                StatusCode::BAD_REQUEST,
            )
        })?;

    let data_hex = claim_log["data"].as_str().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing claim event data"), StatusCode::BAD_REQUEST)
    })?;
    let data_bytes = hex::decode(data_hex.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(anyhow!("Invalid claim event data"), StatusCode::BAD_REQUEST)
    })?;

    if data_bytes.len() < 32 {
        return Err(ErrorResponse::with_status(
            anyhow!("Invalid claim event data"),
            StatusCode::BAD_REQUEST,
        ));
    }

    Ok(U256::from_be_slice(&data_bytes[data_bytes.len() - 32..]))
}

async fn claim_avail_transaction(
    state: &Arc<AppState>,
    block_number: u32,
    tx_index: u32,
    message_id: &str,
) -> anyhow::Result<Response, ErrorResponse> {
    let requested_message_id = validate_message_id(message_id)?;

    let block_hash: String = state
        .avail_client
        .request("chain_getBlockHash", rpc_params![block_number])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block hash: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch block hash"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    // Verify extrinsic exists
    let block: Value = state
        .avail_client
        .request("chain_getBlock", rpc_params![&block_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block: {e:#}");
            ErrorResponse::with_status(anyhow!("Failed to fetch block"), StatusCode::BAD_GATEWAY)
        })?;

    let extrinsics = block["block"]["extrinsics"].as_array().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing extrinsics"), StatusCode::BAD_GATEWAY)
    })?;

    let ext_hex = extrinsics
        .get(tx_index as usize)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ErrorResponse::with_status(
                anyhow!("Extrinsic not found at index {tx_index}"),
                StatusCode::NOT_FOUND,
            )
        })?;

    let ext_bytes = hex::decode(ext_hex.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid extrinsic encoding"),
            StatusCode::BAD_GATEWAY,
        )
    })?;

    let ext_hash_hex = format!("0x{}", hex::encode(blake2_256(&ext_bytes)));
    let indexed_message_id = fetch_avail_claim_message_id_by_ext_hash(state, &ext_hash_hex).await?;
    ensure_message_id_matches(requested_message_id, indexed_message_id)?;

    // Decode sender from extrinsic
    let mut cursor = &ext_bytes[..];
    let decode_err = |e| {
        ErrorResponse::with_status(
            anyhow!("Failed to decode extrinsic: {e}"),
            StatusCode::BAD_GATEWAY,
        )
    };

    <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?;
    let version = u8::decode(&mut cursor).map_err(decode_err)?;

    let sender = if version & 0x80 != 0 {
        let addr_type = u8::decode(&mut cursor).map_err(decode_err)?;
        if addr_type != 0x00 {
            String::new()
        } else {
            let account = <[u8; 32]>::decode(&mut cursor).map_err(decode_err)?;
            AccountId32::new(account).to_ss58check()
        }
    } else {
        String::new()
    };

    let timestamp = fetch_avail_block_timestamp(&state.avail_client, &block_hash).await?;

    sqlx::query_file!(
        "sql/insert_initiated_tx.sql",
        &ext_hash_hex,
        "EthAvail",
        message_id,
        &sender,
        "",
        "0",
        &block_hash,
        block_number as i32,
        tx_index as i32,
        timestamp,
        "claim",
    )
    .execute(&state.db)
    .await?;

    Ok((StatusCode::OK, Json(json!({"status": "ok"}))).into_response())
}

async fn fetch_avail_claim_message_id_by_ext_hash(
    state: &Arc<AppState>,
    ext_hash: &str,
) -> anyhow::Result<U256, ErrorResponse> {
    let message_id_text: Option<String> = sqlx::query_scalar(
        r#"
SELECT aet.message_id::text
FROM avail_execute_table aet
JOIN avail_indexer ai ON ai.id = aet.id
WHERE ai.ext_hash = $1
LIMIT 1
        "#,
    )
    .bind(ext_hash)
    .fetch_optional(&state.db)
    .await?;

    let message_id_text = message_id_text.ok_or_else(|| {
        ErrorResponse::with_status(
            anyhow!("Unable to validate claim messageId from fetched transaction"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    validate_message_id(&message_id_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_message_id_accepts_decimal_u256() {
        assert!(validate_message_id("12965243546238977").is_ok());
    }

    #[test]
    fn validate_message_id_rejects_non_numeric() {
        assert!(validate_message_id("abc123").is_err());
    }

    #[test]
    fn eth_claim_message_id_must_match_receipt() {
        let receipt = json!({
            "logs": [{
                "address": "0x967F7DdC4ec508462231849AE81eeaa68Ad01389",
                "data": "0x000000000000000000000000000000000000000000000000002e0fd200000001"
            }]
        });

        let expected =
            extract_eth_claim_message_id(&receipt, "0x967F7DdC4ec508462231849AE81eeaa68Ad01389")
                .map(|v| v.to_string());

        assert_eq!(expected.ok(), Some("12965243546238977".to_string()));
    }

    #[test]
    fn message_id_match_accepts_equal_values() {
        let requested = U256::from(42);
        let derived = U256::from(42);
        assert!(ensure_message_id_matches(requested, derived).is_ok());
    }

    #[test]
    fn message_id_match_rejects_mismatch() {
        let requested = U256::from(42);
        let derived = U256::from(43);
        assert!(ensure_message_id_matches(requested, derived).is_err());
    }
}
