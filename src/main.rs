use axum::http::StatusCode;
use axum::{
    extract::{Json, Path, Query, State},
    routing::get,
    Router,
};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    rpc_params,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

struct AppState {
    jsonrpc_client: HttpClient,
    succinct_client: Client,
    succinct_base_url: String,
}
#[tokio::main]
async fn main() {
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

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn alive() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({ "name": "Avail Bridge API" })))
}

#[derive(Deserialize)]
struct IndexStruct {
    index: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct DataProofResponse {
    leaf: String,
    leaf_index: usize,
    number_of_leaves: usize,
    proof: Vec<String>,
    root: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct HeaderResponse {
    number: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct SuccinctAPIResponse {
    data: Option<SuccinctAPIData>,
    success: Option<bool>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct SuccinctAPIData {
    range_hash: String,
    data_commitment: String,
    merkle_branch: Vec<String>,
    data_root: String,
    data_root_index: Option<usize>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
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
) -> Result<Json<Value>, StatusCode> {
    let data_proof_response: Result<DataProofResponse, _> = state
        .jsonrpc_client
        .request(
            "kate_queryDataProof",
            rpc_params![index_struct.index, &block_hash],
        )
        .await;
    let data_proof = match data_proof_response {
        Ok(resp) => resp,
        Err(err) => {
            println!("error: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let block_number_response: Result<HeaderResponse, _> = state
        .jsonrpc_client
        .request("chain_getHeader", rpc_params![&block_hash])
        .await;
    let block_number = match block_number_response {
        Ok(resp) => match usize::from_str_radix(&resp.number.trim_start_matches("0x"), 16) {
            Ok(num) => num,
            Err(err) => {
                println!("error: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        },
        Err(err) => {
            println!("error: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
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
                    println!("error: {:?}", "succinct api returned false");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                _ => {
                    println!("error: {:?}", "succinct api returned no data");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            },
            Err(err) => {
                println!("error: {:?}", err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        },
        Err(err) => {
            println!("error: {:?}", err);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Ok(Json(json!(AggregatedResponse {
        data_root_proof: succinct_data.merkle_branch,
        leaf_proof: data_proof.proof,
        range_hash: succinct_data.range_hash,
        // TODO: make non-option when implemented
        data_root_index: succinct_data.data_root_index.unwrap_or(0),
        leaf: data_proof.leaf,
        leaf_index: data_proof.leaf_index,
        data_root: data_proof.root,
        data_root_commitment: succinct_data.data_commitment,
        block_hash: block_hash,
        block_number: block_number,
    })))
}
