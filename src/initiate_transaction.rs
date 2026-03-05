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
                StatusCode::BAD_REQUEST,
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
                StatusCode::BAD_REQUEST,
            )
        })?;
    let bytes = hex::decode(storage_hex.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid timestamp encoding"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    let timestamp_bytes: [u8; 8] =
        bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                ErrorResponse::with_status(
                    anyhow!("Invalid timestamp length"),
                    StatusCode::BAD_REQUEST,
                )
            })?;
    let timestamp_ms = u64::from_le_bytes(timestamp_bytes);
    Ok((timestamp_ms / 1000) as i64)
}

struct AvailBlockExtrinsic {
    block_hash: String,
    ext_hex: String,
}

struct ParsedAvailExtrinsic {
    bytes: Vec<u8>,
    hash_hex: String,
    sender: String,
    call_offset: usize,
}

enum AvailSenderMode {
    Strict,
    Lenient,
}

const VECTOR_PALLET_ID: u8 = 39;
const VECTOR_SEND_MESSAGE_CALL_ID: u8 = 3;

struct DecodedSendMessageCall {
    message: Message,
    to: sp_core::H256,
    domain: u32,
}

async fn fetch_avail_extrinsic_at_index(
    state: &Arc<AppState>,
    block_number: u32,
    tx_index: u32,
) -> anyhow::Result<AvailBlockExtrinsic, ErrorResponse> {
    let block_hash: String = state
        .avail_client
        .request("chain_getBlockHash", rpc_params![block_number])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block hash: {e:#}");
            ErrorResponse::with_status(
                anyhow!("Failed to fetch block hash"),
                StatusCode::BAD_REQUEST,
            )
        })?;

    let block: Value = state
        .avail_client
        .request("chain_getBlock", rpc_params![&block_hash])
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch Avail block: {e:#}");
            ErrorResponse::with_status(anyhow!("Failed to fetch block"), StatusCode::BAD_REQUEST)
        })?;

    let extrinsics = block["block"]["extrinsics"].as_array().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing extrinsics"), StatusCode::BAD_REQUEST)
    })?;

    let ext_hex = extrinsics
        .get(tx_index as usize)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ErrorResponse::with_status(
                anyhow!("Extrinsic not found at index {tx_index}"),
                StatusCode::NOT_FOUND,
            )
        })?
        .to_string();

    Ok(AvailBlockExtrinsic {
        block_hash,
        ext_hex,
    })
}

fn parse_avail_extrinsic(
    ext_hex: &str,
    mode: AvailSenderMode,
) -> anyhow::Result<ParsedAvailExtrinsic, ErrorResponse> {
    let bytes = hex::decode(ext_hex.trim_start_matches("0x")).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid extrinsic encoding"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let hash_hex = format!("0x{}", hex::encode(blake2_256(&bytes)));
    let mut cursor = &bytes[..];
    let decode_err = |e| {
        ErrorResponse::with_status(
            anyhow!("Failed to decode extrinsic: {e}"),
            StatusCode::BAD_REQUEST,
        )
    };

    <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?;
    let version = u8::decode(&mut cursor).map_err(decode_err)?;
    let mut sender = String::new();
    let mut call_offset = bytes.len() - cursor.len();

    if version & 0x80 != 0 {
        let addr_type = u8::decode(&mut cursor).map_err(decode_err)?;
        if addr_type != 0x00 {
            return match mode {
                AvailSenderMode::Lenient => Ok(ParsedAvailExtrinsic {
                    bytes,
                    hash_hex,
                    sender,
                    call_offset,
                }),
                AvailSenderMode::Strict => Err(ErrorResponse::with_status(
                    anyhow!("Unsupported address type"),
                    StatusCode::BAD_REQUEST,
                )),
            };
        }

        let account = <[u8; 32]>::decode(&mut cursor).map_err(decode_err)?;
        sender = AccountId32::new(account).to_ss58check();

        if matches!(mode, AvailSenderMode::Strict) {
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
                        StatusCode::BAD_REQUEST,
                    ));
                }
            }

            let era = u8::decode(&mut cursor).map_err(decode_err)?;
            if era != 0x00 {
                u8::decode(&mut cursor).map_err(decode_err)?;
            }
            <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?;
            <Compact<u128>>::decode(&mut cursor).map_err(decode_err)?;
            <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?;
        }

        call_offset = bytes.len() - cursor.len();
    }

    Ok(ParsedAvailExtrinsic {
        bytes,
        hash_hex,
        sender,
        call_offset,
    })
}

fn decode_send_message_call(
    call_bytes: &[u8],
) -> anyhow::Result<DecodedSendMessageCall, ErrorResponse> {
    let mut cursor = call_bytes;
    let decode_err = |e| {
        ErrorResponse::with_status(
            anyhow!("Failed to decode extrinsic: {e}"),
            StatusCode::BAD_REQUEST,
        )
    };

    let header = <[u8; 2]>::decode(&mut cursor).map_err(decode_err)?;
    if header != [VECTOR_PALLET_ID, VECTOR_SEND_MESSAGE_CALL_ID] {
        return Err(ErrorResponse::with_status(
            anyhow!("Transaction is not a Vector::SendMessage call"),
            StatusCode::BAD_REQUEST,
        ));
    }

    let message = Message::decode(&mut cursor).map_err(decode_err)?;
    let to = sp_core::H256::decode(&mut cursor).map_err(decode_err)?;
    let domain = <Compact<u32>>::decode(&mut cursor).map_err(decode_err)?.0;

    Ok(DecodedSendMessageCall {
        message,
        to,
        domain,
    })
}

async fn initiate_avail_transaction(
    state: &Arc<AppState>,
    block_number: u32,
    tx_index: u32,
) -> anyhow::Result<Response, ErrorResponse> {
    let avail_ext = fetch_avail_extrinsic_at_index(state, block_number, tx_index).await?;
    let parsed_ext = parse_avail_extrinsic(&avail_ext.ext_hex, AvailSenderMode::Strict)?;
    let call = decode_send_message_call(&parsed_ext.bytes[parsed_ext.call_offset..])?;
    let amount = match &call.message {
        Message::FungibleToken { amount, .. } => amount.to_string(),
        _ => "0".to_string(),
    };
    let receiver = format!("0x{}", hex::encode(call.to.as_bytes()));

    // ID matching indexer's (block_height << 32) | ext_index
    let message_id = ((block_number as u64) << 32 | tx_index as u64).to_string();
    let timestamp = fetch_avail_block_timestamp(&state.avail_client, &avail_ext.block_hash).await?;

    sqlx::query_file!(
        "sql/insert_initiated_tx.sql",
        &parsed_ext.hash_hex,
        "AvailEth",
        &message_id,
        &parsed_ext.sender,
        &receiver,
        &amount,
        &avail_ext.block_hash,
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
                StatusCode::BAD_REQUEST,
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

    let sender = extract_eth_claim_sender(&receipt, state.bridge_contract_address.as_str())?;

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
    let claim_log = find_eth_claim_log(receipt, bridge_contract_address)?;

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

fn extract_eth_claim_sender(
    receipt: &Value,
    bridge_contract_address: &str,
) -> anyhow::Result<String, ErrorResponse> {
    let claim_log = find_eth_claim_log(receipt, bridge_contract_address)?;
    let sender_topic = claim_log["topics"][1].as_str().ok_or_else(|| {
        ErrorResponse::with_status(
            anyhow!("Missing claim event sender topic"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let sender_topic_hex = sender_topic.strip_prefix("0x").ok_or_else(|| {
        ErrorResponse::with_status(
            anyhow!("Invalid claim event sender topic"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    if sender_topic_hex.len() != 64 {
        return Err(ErrorResponse::with_status(
            anyhow!("Invalid claim event sender topic"),
            StatusCode::BAD_REQUEST,
        ));
    }

    let sender_bytes = hex::decode(sender_topic_hex).map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid claim event sender topic"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    let sender_array: [u8; 32] = sender_bytes.try_into().map_err(|_| {
        ErrorResponse::with_status(
            anyhow!("Invalid claim event sender topic"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    Ok(AccountId32::new(sender_array).to_ss58check())
}

fn find_eth_claim_log<'a>(
    receipt: &'a Value,
    bridge_contract_address: &str,
) -> anyhow::Result<&'a Value, ErrorResponse> {
    let logs = receipt["logs"].as_array().ok_or_else(|| {
        ErrorResponse::with_status(anyhow!("Missing logs"), StatusCode::BAD_REQUEST)
    })?;

    logs.iter()
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
        })
}

async fn claim_avail_transaction(
    state: &Arc<AppState>,
    block_number: u32,
    tx_index: u32,
    message_id: &str,
) -> anyhow::Result<Response, ErrorResponse> {
    let requested_message_id = validate_message_id(message_id)?;

    let avail_ext = fetch_avail_extrinsic_at_index(state, block_number, tx_index).await?;
    let parsed_ext = parse_avail_extrinsic(&avail_ext.ext_hex, AvailSenderMode::Lenient)?;
    let indexed_message_id =
        fetch_avail_claim_message_id_by_ext_hash(state, &parsed_ext.hash_hex).await?;
    ensure_message_id_matches(requested_message_id, indexed_message_id)?;

    let timestamp = fetch_avail_block_timestamp(&state.avail_client, &avail_ext.block_hash).await?;

    sqlx::query_file!(
        "sql/insert_initiated_tx.sql",
        &parsed_ext.hash_hex,
        "EthAvail",
        message_id,
        &parsed_ext.sender,
        "",
        "0",
        &avail_ext.block_hash,
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
    let message_id_text: Option<String> =
        sqlx::query_file_scalar!("sql/query_avail_claim_message_id.sql", ext_hash)
            .fetch_optional(&state.db)
            .await?
            .flatten();

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
    use parity_scale_codec::Encode;
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
    fn eth_claim_sender_is_decoded_from_claim_event_topic() {
        let receipt = json!({
            "logs": [{
                "address": "0x967F7DdC4ec508462231849AE81eeaa68Ad01389",
                "topics": [
                    "0x4ad8286366216a121ffbecdd11163a134fc364cdf7cc99aae4cc3221d8d92269",
                    "0xcc2fd60dbb2ffedcab868872ea8d8c532759025bb1a9b26c5571dea8da223a3f",
                    "0x00000000000000000000000048e7e157cf873c15a5a6734ea37c000e1cb2383d"
                ],
                "data": "0x000000000000000000000000000000000000000000000000002e0fd200000001"
            }]
        });

        let sender =
            extract_eth_claim_sender(&receipt, "0x967F7DdC4ec508462231849AE81eeaa68Ad01389");

        assert_eq!(
            sender.ok(),
            Some("5GgRqSNN1zTsjA6N7cofcdP9yewA6JG83S649HbuBut8MG4o".to_string())
        );
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

    fn hex_from_extrinsic_body(body: Vec<u8>) -> String {
        let mut ext = Compact(body.len() as u32).encode();
        ext.extend_from_slice(&body);
        format!("0x{}", hex::encode(ext))
    }

    #[test]
    fn parse_avail_extrinsic_strict_extracts_sender_and_call_offset() {
        let mut body = vec![0x84, 0x00];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x22; 64]);
        body.push(0x00);
        body.extend_from_slice(&Compact(0u32).encode());
        body.extend_from_slice(&Compact(0u128).encode());
        body.extend_from_slice(&Compact(0u32).encode());
        body.extend_from_slice(&[0x09, 0x00, 0xAA, 0xBB]);

        let ext_hex = hex_from_extrinsic_body(body);
        let parsed_result = parse_avail_extrinsic(&ext_hex, AvailSenderMode::Strict);
        assert!(parsed_result.is_ok());
        let parsed = parsed_result.ok().unwrap();

        assert_eq!(parsed.sender, AccountId32::new([0x11; 32]).to_ss58check());
        assert_eq!(
            &parsed.bytes[parsed.call_offset..parsed.call_offset + 2],
            &[0x09, 0x00]
        );
        assert!(parsed.hash_hex.starts_with("0x"));
    }

    #[test]
    fn parse_avail_extrinsic_lenient_allows_non_accountid_address_type() {
        let ext_hex = hex_from_extrinsic_body(vec![0x84, 0x01]);
        let parsed_result = parse_avail_extrinsic(&ext_hex, AvailSenderMode::Lenient);
        assert!(parsed_result.is_ok());
        let parsed = parsed_result.ok().unwrap();

        assert_eq!(parsed.sender, "");
        assert!(parsed.hash_hex.starts_with("0x"));
    }

    #[test]
    fn parse_avail_extrinsic_strict_rejects_non_accountid_address_type() {
        let ext_hex = hex_from_extrinsic_body(vec![0x84, 0x01]);
        assert!(parse_avail_extrinsic(&ext_hex, AvailSenderMode::Strict).is_err());
    }

    #[test]
    fn decode_send_message_call_rejects_non_send_message_call() {
        let call = vec![0x09, 0x00, 0xAA, 0xBB];
        assert!(decode_send_message_call(&call).is_err());
    }

    #[test]
    fn decode_send_message_call_decodes_valid_vector_send_message() {
        use parity_scale_codec::Encode;

        let message = Message::FungibleToken {
            asset_id: sp_core::H256::from([0xAB; 32]),
            amount: 42,
        };
        let mut call = vec![VECTOR_PALLET_ID, VECTOR_SEND_MESSAGE_CALL_ID];
        call.extend_from_slice(&message.encode());
        call.extend_from_slice(&sp_core::H256::from([0xCD; 32]).encode());
        call.extend_from_slice(&Compact(7u32).encode());

        let decoded_result = decode_send_message_call(&call);
        assert!(decoded_result.is_ok());
        let decoded = decoded_result.ok().unwrap();
        assert_eq!(decoded.domain, 7);
    }
}
