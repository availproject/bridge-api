use alloy::primitives::{Address, B256};
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::transports::http::reqwest::Url;
use jsonrpsee::http_client::HttpClient;
#[cfg(test)]
use jsonrpsee::http_client::HttpClientBuilder;
use lazy_static::lazy_static;
use reqwest::Client;
use sqlx::PgPool;
use sqlx::postgres::PgConnectOptions;
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct AppState {
    pub avail_client: HttpClient,
    pub ethereum_client: HttpClient,
    pub request_client: Client,
    pub merkle_proof_service_base_url: String,
    pub beaconchain_base_url: String,
    pub avail_chain_name: String,
    pub contract_chain_id: String,
    pub contract_address: String,
    pub bridge_contract_address: String,
    pub eth_head_cache_maxage: u16,
    pub avl_head_cache_maxage: u16,
    pub head_cache_maxage: u16,
    pub avl_proof_cache_maxage: u32,
    pub eth_proof_cache_maxage: u32,
    pub proof_cache_maxage: u32,
    pub eth_proof_failure_cache_maxage: u32,
    pub slot_mapping_cache_maxage: u32,
    pub transactions_cache_maxage: u32,
    pub db: PgPool,
    pub chains: HashMap<u64, Chain>,
    pub helios_update_frequency: u32,
    pub vector_update_frequency: u32,
}

#[derive(Debug)]
pub struct Chain {
    pub provider: RootProvider,
    pub contract_address: Address,
}

lazy_static! {
    pub(crate) static ref SLOT_BLOCK_HEAD: RwLock<Option<(u64, u64, B256, u64)>> =
        RwLock::new(None);
}

/// Parses an RPC URL the way alloy's `ProviderBuilder::connect` did: `localhost:<port>` and
/// `<ip>:<port>` without a scheme mean plain HTTP.
pub(crate) fn parse_rpc_url(rpc_url: &str) -> Option<Url> {
    if rpc_url.starts_with("localhost:") || rpc_url.parse::<std::net::SocketAddr>().is_ok() {
        format!("http://{rpc_url}").parse().ok()
    } else {
        rpc_url.parse().ok()
    }
}

/// Postgres options for the transactions database. `host` can hold a port.
///
/// The user name and the password are set on the options and never go through the URL, so a `/`,
/// `?`, `#` or `%` in them is not read as URL syntax.
///
/// Tabs and line breaks are dropped from both, as the URL parser did when they went through the
/// URL. A secret read from a file often ends with a line break.
pub(crate) fn pg_connect_options(
    host: &str,
    database: &str,
    username: &str,
    password: &str,
) -> Result<PgConnectOptions, sqlx::Error> {
    let options: PgConnectOptions = format!("postgresql://{host}/{database}").parse()?;
    let without_line_breaks = |value: &str| value.replace(['\t', '\n', '\r'], "");
    Ok(options
        .username(&without_line_breaks(username))
        .password(&without_line_breaks(password)))
}

/// One provider per chain, built once, with timeouts so a stalled RPC cannot hold a request.
pub(crate) fn chain_provider(rpc_url: Url) -> RootProvider {
    ProviderBuilder::new()
        .disable_recommended_fillers()
        .with_reqwest(rpc_url, |builder| {
            builder
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap()
        })
}

#[cfg(test)]
pub(crate) fn test_state() -> Arc<AppState> {
    // Nothing listens here, so every request fails at connect.
    let unused_url = "http://127.0.0.1:1";
    Arc::new(AppState {
        avail_client: HttpClientBuilder::default().build(unused_url).unwrap(),
        ethereum_client: HttpClientBuilder::default().build(unused_url).unwrap(),
        request_client: Client::new(),
        merkle_proof_service_base_url: unused_url.to_owned(),
        beaconchain_base_url: unused_url.to_owned(),
        avail_chain_name: "turing".to_owned(),
        contract_chain_id: "11155111".to_owned(),
        contract_address: "0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96".to_owned(),
        bridge_contract_address: "0x967F7DdC4ec508462231849AE81eeaa68Ad01389".to_owned(),
        eth_head_cache_maxage: 240,
        avl_head_cache_maxage: 600,
        head_cache_maxage: 60,
        avl_proof_cache_maxage: 172800,
        eth_proof_cache_maxage: 172800,
        proof_cache_maxage: 172800,
        eth_proof_failure_cache_maxage: 5400,
        slot_mapping_cache_maxage: 172800,
        transactions_cache_maxage: 60,
        db: PgPool::connect_lazy("postgresql://avail:avail@localhost:5432/ui-indexer").unwrap(),
        chains: HashMap::from([(
            1,
            Chain {
                provider: chain_provider(unused_url.parse().unwrap()),
                contract_address: Address::ZERO,
            },
        )]),
        helios_update_frequency: 3600,
        vector_update_frequency: 360,
    })
}

#[test]
fn test_pg_options_drop_line_breaks_and_tabs_from_credentials() {
    use sqlx::ConnectOptions;

    // A secret read from a file often ends with a line break. Such a password worked when the
    // credentials went through the URL, because the URL parser drops tabs and line breaks.
    let options =
        pg_connect_options("db.example:6432", "ui-indexer", "avail\n", "sec\tret\r\n").unwrap();
    assert_eq!(options.get_username(), "avail");
    assert_eq!(options.to_url_lossy().password(), Some("secret"));
}

#[test]
fn test_pg_options_take_the_password_as_it_is() {
    use sqlx::ConnectOptions;

    // What sqlx connects with. `to_url_lossy` percent-encodes the password.
    let read =
        |password| match pg_connect_options("db.example:6432", "ui-indexer", "avail", password) {
            Ok(options) => format!(
                "{}@{}:{}/{} password={}",
                options.get_username(),
                options.get_host(),
                options.get_port(),
                options.get_database().unwrap_or_default(),
                options.to_url_lossy().password().unwrap_or_default()
            ),
            Err(e) => e.to_string(),
        };
    assert_eq!(
        ["ab/cd", "12?rest", "ab#cd", "ab%41cd"].map(read),
        [
            "avail@db.example:6432/ui-indexer password=ab%2Fcd",
            "avail@db.example:6432/ui-indexer password=12%3Frest",
            "avail@db.example:6432/ui-indexer password=ab%23cd",
            "avail@db.example:6432/ui-indexer password=ab%2541cd",
        ]
    );
}

#[test]
fn test_rpc_url_without_scheme_means_http() {
    let parsed = |s| parse_rpc_url(s).map(|url| url.to_string());
    assert_eq!(parsed("localhost:8545").unwrap(), "http://localhost:8545/");
    assert_eq!(parsed("127.0.0.1:8545").unwrap(), "http://127.0.0.1:8545/");
    assert_eq!(
        parsed("https://rpc.example/path").unwrap(),
        "https://rpc.example/path"
    );
    assert_eq!(parsed("not a url"), None);
}
