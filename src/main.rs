mod beacon;
mod contracts;
mod error;
mod heads;
mod proofs;
pub mod state;
mod transactions;

use crate::heads::{get_avl_head, get_eth_head, get_head, track_slot_avail_task};
use crate::proofs::{get_avl_proof, get_eth_proof, get_proof};
use crate::state::{AppState, Chain, chain_provider, parse_rpc_url};
use crate::transactions::transactions;

use alloy::primitives::Address;
use anyhow::Context;
use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    routing::get,
};
use http::Method;
use jsonrpsee::http_client::HttpClientBuilder;
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::{env, process, time::Duration};
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{Level, Subscriber, warn};
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::prelude::*;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

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

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    subscriber(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "bridge_api=debug,tower_http=debug,axum::rejection=trace".into()),
    )
    .init();

    let max_concurrent_request: usize = env::var("MAX_CONCURRENT_REQUEST")
        .ok()
        .and_then(|max_request| max_request.parse::<usize>().ok())
        .unwrap_or(1024);

    let db_url: String = env::var("POSTGRES_URL").unwrap_or("localhost:5432".to_owned());
    // Connection pool
    let connections_string = format!(
        "postgresql://{}:{}@{}/{}",
        env::var("PG_USERNAME").unwrap_or("avail".to_owned()),
        env::var("PG_PASSWORD").unwrap_or("avail".to_owned()),
        db_url,
        env::var("POSTGRES_DB").unwrap_or("ui-indexer".to_owned()),
    );

    let db = PgPool::connect(&connections_string)
        .await
        .context("Cannot get connection pool")
        .unwrap();

    const SUPPORTED_CHAIN_IDS: [u64; 7] = [1, 123, 32657, 84532, 11155111, 17000, 421614];
    // loop through expected_chain_ids and store the chain information, if value is missing, skip chain_id
    let chains = SUPPORTED_CHAIN_IDS
        .iter()
        .filter_map(|&chain_id| {
            let rpc_url = env::var(format!("CHAIN_{}_RPC_URL", chain_id)).ok()?;
            let Some(rpc_url) = parse_rpc_url(&rpc_url) else {
                warn!("CHAIN_{chain_id}_RPC_URL is not a valid URL, skipping chain");
                return None;
            };
            let contract_address = env::var(format!("CHAIN_{}_CONTRACT_ADDRESS", chain_id))
                .ok()
                .and_then(|addr| addr.parse::<Address>().ok())?;
            Some((
                chain_id,
                Chain {
                    provider: chain_provider(rpc_url),
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
        request_client: Client::builder()
            .brotli(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap(),
        merkle_proof_service_base_url: env::var("MERKLE_PROOF_SERVICE_URL")
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
        db,
        chains,
        helios_update_frequency: env::var("HELIOS_UPDATE_FREQUENCY")
            .ok()
            .and_then(|helios_update_frequency| helios_update_frequency.parse::<u32>().ok())
            .unwrap_or(3600),
        vector_update_frequency: env::var("VECTOR_UPDATE_FREQUENCY")
            .ok()
            .and_then(|vector_update_frequency| vector_update_frequency.parse::<u32>().ok())
            .unwrap_or(360),
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/versions", get(versions))
        .route("/v1/info", get(info))
        .route("/v1/eth/proof/{block_hash}", get(get_eth_proof)) // get proof from avail for ethereum
        .route("/v1/eth/head", get(get_eth_head)) // fetch head form eth contract
        .route("/v1/avl/head", get(get_avl_head)) // fetch head form avail pallet
        .route(
            "/v1/avl/proof/{block_hash}/{message_id}",
            get(get_avl_proof), // get proof from ethereum for avail
        )
        .route("/v1/transactions", get(transactions)) // fetch all transaction
        .route("/transactions", get(transactions))
        .route("/v1/head/{chain_id}", get(get_head)) // get head based on chain
        .route("/v1/proof/{chain_id}", get(get_proof)) // get proof for avail based on chain
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

/// Structured JSON logs, filtered by `env_filter`.
fn subscriber(env_filter: tracing_subscriber::EnvFilter) -> impl Subscriber + Send + Sync {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json())
        .with(env_filter)
        .with(limit_transport_logging())
}

/// Limit alloy HTTP transport logging to `info`, whatever `RUST_LOG` enables.
fn limit_transport_logging() -> FilterFn {
    FilterFn::new(|metadata| {
        !(metadata.target().starts_with("alloy_transport_http") && *metadata.level() > Level::INFO)
    })
}

#[test]
fn test_alloy_http_logging_is_limited_to_info() {
    // Same target and field as the span that alloy's HTTP transport opens for each request.
    for directives in [
        "debug",
        "alloy_transport_http=trace",
        "info,alloy_transport_http=trace",
    ] {
        tracing::subscriber::with_default(
            subscriber(tracing_subscriber::EnvFilter::new(directives)),
            || {
                let span = tracing::debug_span!(
                    target: "alloy_transport_http::reqwest_transport",
                    "ReqwestTransport",
                    url = "http://rpc.example/path"
                );
                assert!(span.is_disabled(), "{directives}");
            },
        );
    }
}
