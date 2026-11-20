//! Helpers that only the tests use.

use alloy::primitives::B256;
use axum::{Json, Router};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tracing::subscriber::DefaultGuard;

/// Serves `router` on a free local port and returns the URL.
pub(crate) async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await });
    url
}

/// Plays the Avail RPC and a chain RPC: it answers every method that the handlers and the head
/// task call. Mount it with `Router::new().route("/", post(rpc))`.
pub(crate) async fn rpc(Json(request): Json<Value>) -> Json<Value> {
    let zero = B256::ZERO;
    let result = match request["method"].as_str().unwrap() {
        "chain_getFinalizedHead" => json!(zero),
        // The Vector head and its timestamp: the SCALE form of 100.
        "state_getStorage" => json!("0x6400000000000000"),
        "chain_getHeader" => json!({"number": "0x5"}),
        // latestBlock() = 10, so block 5 is in the range.
        "eth_call" => json!(B256::with_last_byte(10)),
        "kate_queryDataProof" => json!({"dataProof": {
            "roots": {"dataRoot": zero, "blobRoot": zero, "bridgeRoot": zero},
            "proof": [],
            "leafIndex": 0,
            "leaf": zero,
        }}),
        method => panic!("unexpected RPC method {method}"),
    };
    Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
}

/// Collects the log lines of one test.
///
/// tracing caches, per log call site, whether a subscriber wants the event. A test that reaches a
/// call site on a thread without a subscriber can cache "no" first, and then a test that captures
/// the log gets nothing from that call site. So every test that reaches a call site whose line
/// some test checks must capture the log too.
#[derive(Clone, Default)]
pub(crate) struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    /// Collects the log lines of the current thread until the guard is dropped.
    pub(crate) fn capture() -> (Self, DefaultGuard) {
        let log = Self::default();
        let writer = log.clone();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        (log, guard)
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
