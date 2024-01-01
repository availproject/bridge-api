use alloy_primitives::B256;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use jemallocator::Jemalloc;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::sync::Arc;
use tokio::join;
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

use tracing_subscriber::prelude::*;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

struct AppState {
    jsonrpc_client: HttpClient,
    succinct_client: Client,
    succinct_base_url: String,
}

#[derive(Deserialize)]
struct IndexStruct {
    index: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataProofResponse {
    leaf: B256,
    leaf_index: u32,
    proof: Vec<B256>,
    root: B256,
}

#[derive(Deserialize)]
struct SuccinctAPIResponse {
    data: Option<SuccinctAPIData>,
    success: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuccinctAPIData {
    range_hash: B256,
    data_commitment: B256,
    merkle_branch: Vec<B256>,
    index: u8,
    block_number: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregatedResponse {
    data_root_proof: Vec<B256>,
    leaf_proof: Vec<B256>,
    range_hash: B256,
    data_root_index: u8,
    leaf: B256,
    leaf_index: u32,
    data_root: B256,
    data_root_commitment: B256,
    block_hash: B256,
    block_number: usize,
}

async fn alive() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({ "name": "Avail Bridge API" })))
}

async fn get_proof(
    Path(block_hash): Path<B256>,
    Query(index_struct): Query<IndexStruct>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let cloned_state = state.clone();
    let data_proof_response_fut = tokio::spawn(async move {
        cloned_state
            .jsonrpc_client
            .request(
                "kate_queryDataProof",
                rpc_params![index_struct.index, &block_hash],
            )
            .await
    });
    let succinct_response_fut = tokio::spawn(async move {
        state
            .succinct_client
            .get(format!("{}{}", state.succinct_base_url, block_hash))
            .send()
            .await
    });
    let (data_proof, succinct_response) = join!(data_proof_response_fut, succinct_response_fut);
    let data_proof: DataProofResponse = match data_proof.unwrap() {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!("❌ {:?}", err);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string()})),
            );
        }
    };
    let succinct_data = match succinct_response.unwrap() {
        Ok(resp) => match resp.json::<SuccinctAPIResponse>().await {
            Ok(data) => match data {
                SuccinctAPIResponse {
                    data: Some(data), ..
                } => data,
                SuccinctAPIResponse {
                    success: Some(false),
                    ..
                } => {
                    tracing::error!("❌ Succinct API returned unsuccessfully");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Succinct API returned unsuccessfully" })),
                    );
                }
                _ => {
                    tracing::error!("❌ Succinct API returned no data");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Succinct API returned no data"})),
                    );
                }
            },
            Err(err) => {
                tracing::error!("❌ {:?}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string()})),
                );
            }
        },
        Err(err) => {
            tracing::error!("❌ {:?}", err);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string()})),
            );
        }
    };
    (
        StatusCode::OK,
        Json(json!(AggregatedResponse {
            data_root_proof: succinct_data.merkle_branch,
            leaf_proof: data_proof.proof,
            range_hash: succinct_data.range_hash,
            data_root_index: succinct_data.index,
            leaf: data_proof.leaf,
            leaf_index: data_proof.leaf_index,
            data_root: data_proof.root,
            data_root_commitment: succinct_data.data_commitment,
            block_hash,
            block_number: succinct_data.block_number,
        })),
    )
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().unwrap();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "bridge_api=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .init();

    let shared_state = Arc::new(AppState {
        jsonrpc_client: HttpClientBuilder::default()
            .build(env::var("JSONRPC_URL").unwrap_or("https://goldberg.avail.tools/api".to_owned()))
            .unwrap(),
        succinct_client: Client::builder().brotli(true).build().unwrap(),
        succinct_base_url: env::var("SUCCINCT_URL")
            .unwrap_or("https://beaconapi.succinct.xyz/api/integrations/vectorx/".to_owned()),
    });

    let app = Router::new()
        .route("/", get(alive))
        .route("/proof/:block_hash", get(get_proof))
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .with_state(shared_state);

    let host = env::var("HOST").unwrap_or("0.0.0.0".to_owned());
    let port = env::var("PORT").unwrap_or("8080".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap();
    tracing::info!("🚀 Listening on {} port {}", host, port);
    axum::serve(listener, app).await.unwrap();
}
