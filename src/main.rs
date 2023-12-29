use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use jemallocator::Jemalloc;
use jsonrpsee::{
    core::{client::ClientT, Error},
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::{pin::Pin, sync::Arc};
use tokio::{macros::support::Future, try_join};
use tracing;
use tracing_subscriber;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

struct AppState {
    jsonrpc_client: HttpClient,
    succinct_client: Client,
    succinct_base_url: String,
}
#[tokio::main]
async fn main() {
    dotenvy::dotenv().unwrap();
    tracing_subscriber::fmt::init();
    let shared_state = Arc::new(AppState {
        jsonrpc_client: HttpClientBuilder::default()
            .build("https://goldberg.avail.tools/api")
            .unwrap(),
        succinct_client: Client::builder().brotli(true).build().unwrap(),
        succinct_base_url: "https://beaconapi.succinct.xyz/api/integrations/vectorx/".to_owned(),
    });
    // build our application with a single route
    let app = Router::new()
        .route("/", get(alive))
        .route("/proof/:block_hash", get(get_proof))
        .with_state(shared_state);

    let host = env::var("HOST").unwrap_or("0.0.0.0".to_owned());
    let port = env::var("PORT").unwrap_or("8080".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap();
    tracing::info!("🚀 Listening on {} port {}", host, port);
    axum::serve(listener, app).await.unwrap();
}

async fn alive() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({ "name": "Avail Bridge API" })))
}

#[derive(Deserialize, Debug)]
struct IndexStruct {
    index: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DataProofResponse {
    leaf: String,
    leaf_index: usize,
    // number_of_leaves: usize,
    proof: Vec<String>,
    root: String,
}

#[derive(Deserialize, Debug)]
struct HeaderResponse {
    number: String,
}

#[derive(Deserialize, Debug)]
struct SuccinctAPIResponse {
    data: Option<SuccinctAPIData>,
    success: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SuccinctAPIData {
    range_hash: String,
    data_commitment: String,
    merkle_branch: Vec<String>,
    // data_root: String,
    data_root_index: Option<usize>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AggregatedResponse {
    data_root_proof: Vec<String>,
    leaf_proof: Vec<String>,
    range_hash: String,
    data_root_index: usize,
    leaf: String,
    leaf_index: usize,
    data_root: String,
    data_root_commitment: String,
    block_hash: String,
    block_number: usize,
}

async fn get_proof(
    Path(block_hash): Path<String>,
    Query(index_struct): Query<IndexStruct>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let data_proof_response_fut: Pin<
        Box<dyn Future<Output = Result<DataProofResponse, Error>> + Send>,
    > = state.jsonrpc_client.request(
        "kate_queryDataProof",
        rpc_params![index_struct.index, &block_hash],
    );
    let block_number_response_fut: Pin<
        Box<dyn Future<Output = Result<HeaderResponse, Error>> + Send>,
    > = state
        .jsonrpc_client
        .request("chain_getHeader", rpc_params![&block_hash]);
    let (data_proof, block_number_response) =
        match try_join!(data_proof_response_fut, block_number_response_fut) {
            Ok((res_1, res_2)) => (res_1, res_2),
            Err(err) => {
                tracing::error!("❌ {:?}", err);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": err.to_string() })),
                );
            }
        };
    let block_number =
        match usize::from_str_radix(&block_number_response.number.trim_start_matches("0x"), 16) {
            Ok(num) => num,
            Err(err) => {
                tracing::error!("❌ {:?}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string()})),
                );
            }
        };
    let succinct_response = state
        .succinct_client
        .get(format!("{}{}", state.succinct_base_url, block_number))
        .send()
        .await;
    let succinct_data = match succinct_response {
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
                StatusCode::INTERNAL_SERVER_ERROR,
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
            // TODO: make non-option when implemented
            data_root_index: succinct_data.data_root_index.unwrap_or(1),
            leaf: data_proof.leaf,
            leaf_index: data_proof.leaf_index,
            data_root: data_proof.root,
            data_root_commitment: succinct_data.data_commitment,
            block_hash: block_hash,
            block_number: block_number,
        })),
    )
}
