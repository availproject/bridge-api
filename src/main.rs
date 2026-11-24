mod beacon;
mod config;
mod contracts;
mod error;
mod heads;
mod proofs;
pub mod state;
#[cfg(test)]
mod test_util;
mod transactions;

use crate::config::Config;
use crate::heads::{get_avl_head, get_eth_head, get_head, track_slot_avail_task};
use crate::proofs::{get_avl_proof, get_eth_proof, get_proof};
use crate::state::{AppState, Chain, chain_provider, pg_connect_options};
use crate::transactions::transactions;

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
use std::{process, time::Duration};
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

async fn info(State(state): State<Arc<AppState>>) -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "vectorXContractAddress": state.config.contract_address,
        "vectorXChainId": state.config.contract_chain_id,
        "bridgeContractAddress" : state.config.bridge_contract_address,
        "availChainName": state.config.avail_chain_name,
    })))
}

async fn versions() -> Result<Json<Value>, StatusCode> {
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

    let (config, warnings) = Config::from_env().unwrap_or_else(|e| {
        tracing::error!("Invalid settings: {e:#}");
        process::exit(1);
    });
    for warning in warnings {
        warn!("{warning}");
    }

    // Connection pool
    let db_options = pg_connect_options(
        &config.postgres_url,
        &config.postgres_db,
        &config.pg_username,
        &config.pg_password,
    )
    .context("Cannot get connection pool")
    .unwrap();

    let db = PgPool::connect_with(db_options)
        .await
        .context("Cannot get connection pool")
        .unwrap();

    let chains = config
        .chains
        .iter()
        .map(|chain| {
            (
                chain.chain_id,
                Chain {
                    provider: chain_provider(chain.rpc_url.clone()),
                    contract_address: chain.contract_address,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    let (host, port) = (config.host.clone(), config.port.clone());
    let shared_state = Arc::new(AppState {
        avail_client: HttpClientBuilder::default()
            .max_concurrent_requests(config.max_concurrent_request)
            .build(&config.avail_client_url)
            .unwrap(),
        ethereum_client: HttpClientBuilder::default()
            .max_concurrent_requests(config.max_concurrent_request)
            .build(&config.ethereum_client_url)
            .unwrap(),
        request_client: Client::builder()
            .brotli(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap(),
        db,
        chains,
        config,
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/versions", get(versions))
        .route("/v1/info", get(info))
        .route("/v1/eth/proof/{block_hash}", get(get_eth_proof)) // get proof from avail for ethereum
        .route("/v1/eth/head", get(get_eth_head)) // fetch head from avail pallet
        .route("/v1/avl/head", get(get_avl_head)) // fetch head from eth contract
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

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap();

    tokio::spawn(async move {
        tracing::info!("Starting head tracking task");
        let e = track_slot_avail_task(shared_state.clone()).await;
        tracing::error!("Error occurred, cannot continue: {e:#}");
        process::exit(1);
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
