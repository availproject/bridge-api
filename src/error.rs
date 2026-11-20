use alloy::transports::http::reqwest::Error as AlloyReqwestError;
use alloy::transports::{RpcError, TransportErrorKind};
use axum::Json;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::json;

pub struct ErrorResponse {
    pub error: anyhow::Error,
    pub headers_keypairs: Vec<(String, String)>,
    pub status_code: Option<StatusCode>,
}

impl ErrorResponse {
    /// The answer for a failed upstream request: 500 with the fixed text of `error`.
    pub fn upstream_failed(error: UpstreamError) -> Self {
        Self::with_status_and_headers(
            anyhow::anyhow!(error),
            StatusCode::INTERNAL_SERVER_ERROR,
            &[("Cache-Control", "public, max-age=60, must-revalidate")],
        )
    }

    pub fn with_status(error: anyhow::Error, status_code: StatusCode) -> Self {
        Self {
            error,
            headers_keypairs: vec![],
            status_code: Some(status_code),
        }
    }

    pub fn with_status_and_headers(
        error: anyhow::Error,
        status_code: StatusCode,
        headers: &[(&str, &str)],
    ) -> Self {
        let h = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>();
        Self {
            error,
            headers_keypairs: h,
            status_code: Some(status_code),
        }
    }
}

// Tell axum how to convert `ErrorResponse` into a response.
impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = self
            .status_code
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut headermap = HeaderMap::new();
        for (k, v) in self.headers_keypairs {
            headermap.insert(
                HeaderName::try_from(k).unwrap(),
                HeaderValue::try_from(v).unwrap(),
            );
        }
        let json_resp = Json(json!({"error" : format!("{:#}", self.error)}));

        (status, headermap, json_resp).into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, ErrorResponse>`. That way you don't need to do that manually.
impl<E> From<E> for ErrorResponse
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self {
            error: err.into(),
            headers_keypairs: vec![],
            status_code: None,
        }
    }
}

/// Fixed-text error for failed upstream requests.
pub enum UpstreamError {
    Rpc,
    Beacon,
    MerkleProofService,
    Database,
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UpstreamError::Rpc => "chain RPC request failed",
            UpstreamError::Beacon => "beacon request failed",
            UpstreamError::MerkleProofService => "merkle proof service request failed",
            UpstreamError::Database => "database request failed",
        })
    }
}

// Debug prints the same fixed text, so log lines that use {:?} read the same.
impl std::fmt::Debug for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for UpstreamError {}

/// Why an upstream request failed, as a fixed word for the log.
///
/// It is built from the checks of a library error and never holds its text, so it cannot hold a
/// URL.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FailureKind {
    Timeout,
    Connect,
    /// The answer could not be read or decoded.
    BadResponse,
    /// The upstream answered with an error: an HTTP error status or a JSON-RPC error.
    ErrorResponse,
    Other,
}

impl FailureKind {
    fn of_request(timeout: bool, connect: bool, body_or_decode: bool) -> Self {
        if timeout {
            FailureKind::Timeout
        } else if connect {
            FailureKind::Connect
        } else if body_or_decode {
            FailureKind::BadResponse
        } else {
            FailureKind::Other
        }
    }
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FailureKind::Timeout => "timeout",
            FailureKind::Connect => "connect failed",
            FailureKind::BadResponse => "bad response",
            FailureKind::ErrorResponse => "error response",
            FailureKind::Other => "other",
        })
    }
}

impl From<&reqwest::Error> for FailureKind {
    fn from(e: &reqwest::Error) -> Self {
        Self::of_request(e.is_timeout(), e.is_connect(), e.is_body() || e.is_decode())
    }
}

/// alloy sends its requests with its own reqwest version, so this is not the type above.
impl From<&AlloyReqwestError> for FailureKind {
    fn from(e: &AlloyReqwestError) -> Self {
        Self::of_request(e.is_timeout(), e.is_connect(), e.is_body() || e.is_decode())
    }
}

impl From<&alloy::contract::Error> for FailureKind {
    fn from(e: &alloy::contract::Error) -> Self {
        use alloy::contract::Error;

        match e {
            Error::TransportError(RpcError::Transport(TransportErrorKind::Custom(source))) => {
                match source.downcast_ref::<AlloyReqwestError>() {
                    Some(e) => e.into(),
                    None => FailureKind::Other,
                }
            }
            Error::TransportError(
                RpcError::Transport(TransportErrorKind::HttpError(_)) | RpcError::ErrorResp(_),
            ) => FailureKind::ErrorResponse,
            Error::TransportError(RpcError::DeserError { .. } | RpcError::NullResp)
            | Error::ZeroData(..)
            | Error::AbiError(_) => FailureKind::BadResponse,
            _ => FailureKind::Other,
        }
    }
}

/// What a request to `router` fails with, for a client that waits 200 ms.
#[cfg(test)]
async fn request_failure(router: axum::Router) -> FailureKind {
    let url = crate::test_util::serve(router).await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(200))
        .build()
        .unwrap();
    let result = match client.get(url).send().await {
        Ok(response) => response.json::<serde_json::Value>().await,
        Err(e) => Err(e),
    };
    FailureKind::from(&result.unwrap_err())
}

#[tokio::test]
async fn test_failure_kind_of_a_request() {
    use axum::Router;
    use std::time::Duration;

    let refused = reqwest::get("http://127.0.0.1:1").await.unwrap_err();
    assert_eq!(FailureKind::from(&refused), FailureKind::Connect);

    let slow =
        Router::new().fallback(|| async { tokio::time::sleep(Duration::from_secs(5)).await });
    assert_eq!(request_failure(slow).await, FailureKind::Timeout);

    let not_json = Router::new().fallback(|| async { "this is not json" });
    assert_eq!(request_failure(not_json).await, FailureKind::BadResponse);
}

/// What `latestBlock()` fails with when the chain RPC is at `rpc_url`.
#[cfg(test)]
async fn contract_call_failure(rpc_url: &str) -> FailureKind {
    use crate::contracts::SP1Vector;
    use crate::state::chain_provider;
    use alloy::primitives::Address;

    let provider = chain_provider(rpc_url.parse().unwrap());
    let contract = SP1Vector::new(Address::ZERO, provider);
    FailureKind::from(&contract.latestBlock().call().await.unwrap_err())
}

#[tokio::test]
async fn test_failure_kind_of_a_contract_call() {
    use crate::test_util::serve;
    use axum::Router;
    use serde_json::Value;

    assert_eq!(
        contract_call_failure("http://127.0.0.1:1").await,
        FailureKind::Connect
    );

    let http_error = Router::new().fallback(|| async { StatusCode::BAD_GATEWAY });
    assert_eq!(
        contract_call_failure(&serve(http_error).await).await,
        FailureKind::ErrorResponse
    );

    let rpc_error = Router::new().fallback(|Json(request): Json<Value>| async move {
        let error = json!({"code": -32000, "message": "execution reverted"});
        Json(json!({"jsonrpc": "2.0", "id": request["id"], "error": error}))
    });
    assert_eq!(
        contract_call_failure(&serve(rpc_error).await).await,
        FailureKind::ErrorResponse
    );

    let not_json = Router::new().fallback(|| async { "this is not json" });
    assert_eq!(
        contract_call_failure(&serve(not_json).await).await,
        FailureKind::BadResponse
    );

    // An address without code answers with no data.
    let no_data = Router::new().fallback(|Json(request): Json<Value>| async move {
        Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": "0x"}))
    });
    assert_eq!(
        contract_call_failure(&serve(no_data).await).await,
        FailureKind::BadResponse
    );
}

#[test]
fn test_failure_kind_words() {
    let words = [
        FailureKind::Timeout,
        FailureKind::Connect,
        FailureKind::BadResponse,
        FailureKind::ErrorResponse,
        FailureKind::Other,
    ]
    .map(|kind| kind.to_string());
    assert_eq!(
        words,
        [
            "timeout",
            "connect failed",
            "bad response",
            "error response",
            "other"
        ]
    );
}
