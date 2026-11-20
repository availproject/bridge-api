use crate::state::parse_rpc_url;

use alloy::primitives::Address;
use alloy::transports::http::reqwest::Url;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::env;
use std::str::FromStr;

/// The chains that `CHAIN_<id>_RPC_URL` and `CHAIN_<id>_CONTRACT_ADDRESS` can configure.
pub const SUPPORTED_CHAIN_IDS: [u64; 7] = [1, 123, 32657, 84532, 11155111, 17000, 421614];

/// Every setting of the service. It is read once, at startup.
///
/// A network setting has no default, so a deployment cannot reach another network by leaving one
/// out. An error or a warning names the setting and never holds its value, because a value can
/// be a secret.
pub struct Config {
    pub host: String,
    pub port: String,
    pub max_concurrent_request: usize,
    pub postgres_url: String,
    pub postgres_db: String,
    pub pg_username: String,
    pub pg_password: String,
    pub avail_client_url: String,
    pub ethereum_client_url: String,
    pub merkle_proof_service_base_url: String,
    pub beaconchain_base_url: String,
    pub contract_address: String,
    pub contract_chain_id: String,
    pub avail_chain_name: String,
    pub bridge_contract_address: String,
    pub eth_head_cache_maxage: u16,
    pub avl_head_cache_maxage: u16,
    pub head_cache_maxage: u16,
    pub eth_proof_cache_maxage: u32,
    pub proof_cache_maxage: u32,
    pub eth_proof_failure_cache_maxage: u32,
    pub avl_proof_cache_maxage: u32,
    pub helios_update_frequency: u32,
    pub vector_update_frequency: u32,
    pub chains: Vec<ChainConfig>,
}

pub struct ChainConfig {
    pub chain_id: u64,
    pub rpc_url: Url,
    pub contract_address: Address,
}

impl Config {
    /// Reads the settings from the process environment. See `from_vars`.
    pub fn from_env() -> Result<(Config, Vec<String>)> {
        // A name or a value that is not valid Unicode counts as not set, as with `env::var`.
        let vars = env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self::from_vars(&vars)
    }

    /// Reads the settings from `vars`. It returns the settings and a warning for each chain
    /// setting that is skipped. The error names every setting that is missing or wrong.
    pub fn from_vars(vars: &HashMap<String, String>) -> Result<(Config, Vec<String>)> {
        let mut read = Reader {
            vars,
            problems: vec![],
        };
        let mut warnings = vec![];
        let config = Config {
            avail_client_url: read.required("AVAIL_CLIENT_URL"),
            ethereum_client_url: read.required("ETHEREUM_CLIENT_URL"),
            merkle_proof_service_base_url: read.required("MERKLE_PROOF_SERVICE_URL"),
            beaconchain_base_url: read.required("BEACONCHAIN_URL"),
            contract_address: read.required("VECTORX_CONTRACT_ADDRESS"),
            contract_chain_id: read.required("CONTRACT_CHAIN_ID"),
            avail_chain_name: read.required("AVAIL_CHAIN_NAME"),
            bridge_contract_address: read.required("BRIDGE_CONTRACT_ADDRESS"),
            max_concurrent_request: read.number("MAX_CONCURRENT_REQUEST", 1024),
            eth_head_cache_maxage: read.number("ETH_HEAD_CACHE_MAXAGE", 240),
            avl_head_cache_maxage: read.number("AVL_HEAD_CACHE_MAXAGE", 600),
            head_cache_maxage: read.number("HEAD_CACHE_MAXAGE", 60),
            eth_proof_cache_maxage: read.number("ETH_PROOF_CACHE_MAXAGE", 172800),
            proof_cache_maxage: read.number("PROOF_CACHE_MAXAGE", 172800),
            eth_proof_failure_cache_maxage: read.number("ETH_PROOF_FAILURE_CACHE_MAXAGE", 5400),
            avl_proof_cache_maxage: read.number("AVL_PROOF_CACHE_MAXAGE", 172800),
            helios_update_frequency: read.number("HELIOS_UPDATE_FREQUENCY", 3600),
            vector_update_frequency: read.number("VECTOR_UPDATE_FREQUENCY", 360),
            host: read.or_default("HOST", "0.0.0.0"),
            port: read.or_default("PORT", "8080"),
            postgres_url: read.or_default("POSTGRES_URL", "localhost:5432"),
            postgres_db: read.or_default("POSTGRES_DB", "ui-indexer"),
            pg_username: read.or_default("PG_USERNAME", "avail"),
            pg_password: read.or_default("PG_PASSWORD", "avail"),
            chains: chains(vars, &mut warnings),
        };
        if read.problems.is_empty() {
            Ok((config, warnings))
        } else {
            Err(anyhow!("{}", read.problems.join(", ")))
        }
    }
}

/// Reads settings and collects every problem, so that one start shows all of them.
struct Reader<'a> {
    vars: &'a HashMap<String, String>,
    problems: Vec<String>,
}

impl Reader<'_> {
    /// The value of a setting that is set and not empty.
    fn value(&self, name: &str) -> Option<&str> {
        let value = self.vars.get(name)?;
        (!value.is_empty()).then_some(value.as_str())
    }

    /// A network setting. It has no default.
    fn required(&mut self, name: &str) -> String {
        match self.value(name) {
            Some(value) => value.to_owned(),
            None => {
                self.problems.push(format!("{name} is not set"));
                String::new()
            }
        }
    }

    /// A number. It is `default` when the setting is not set or empty.
    fn number<T: FromStr>(&mut self, name: &str, default: T) -> T {
        match self.value(name).map(str::parse) {
            None => default,
            Some(Ok(number)) => number,
            Some(Err(_)) => {
                self.problems.push(format!("{name} is not a valid number"));
                default
            }
        }
    }

    /// A setting with a default for local runs. An empty value is used as it is.
    fn or_default(&self, name: &str, default: &str) -> String {
        self.vars
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    }
}

/// Reads the chains. A chain setting that cannot be used is skipped and gets a warning.
fn chains(vars: &HashMap<String, String>, warnings: &mut Vec<String>) -> Vec<ChainConfig> {
    let mut chains = vec![];
    for chain_id in SUPPORTED_CHAIN_IDS {
        match chain(chain_id, vars) {
            Ok(Some(chain)) => chains.push(chain),
            Ok(None) => {}
            Err(warning) => warnings.push(warning),
        }
    }

    let mut ignored: Vec<_> = vars
        .keys()
        .filter_map(|name| {
            let chain_id = chain_id_in(name)?;
            (!SUPPORTED_CHAIN_IDS.contains(&chain_id))
                .then(|| format!("{name} is ignored, because chain {chain_id} is not supported"))
        })
        .collect();
    ignored.sort();
    warnings.extend(ignored);

    chains
}

/// Reads one chain. `Ok(None)` means that the chain is not set, and the error is the warning.
fn chain(chain_id: u64, vars: &HashMap<String, String>) -> Result<Option<ChainConfig>, String> {
    let rpc_url_name = format!("CHAIN_{chain_id}_RPC_URL");
    let address_name = format!("CHAIN_{chain_id}_CONTRACT_ADDRESS");
    let (rpc_url, address) = match (vars.get(&rpc_url_name), vars.get(&address_name)) {
        (None, None) => return Ok(None),
        (None, Some(_)) => return Err(format!("{rpc_url_name} is not set, skipping chain")),
        (Some(rpc_url), address) => (rpc_url, address),
    };
    let rpc_url = parse_rpc_url(rpc_url)
        .ok_or_else(|| format!("{rpc_url_name} is not a valid URL, skipping chain"))?;
    let address = address.ok_or_else(|| format!("{address_name} is not set, skipping chain"))?;
    let contract_address = address
        .parse()
        .map_err(|_| format!("{address_name} is not a valid address, skipping chain"))?;
    Ok(Some(ChainConfig {
        chain_id,
        rpc_url,
        contract_address,
    }))
}

/// The chain id in a name like `CHAIN_<id>_RPC_URL`.
fn chain_id_in(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("CHAIN_")?;
    let chain_id = rest
        .strip_suffix("_RPC_URL")
        .or_else(|| rest.strip_suffix("_CONTRACT_ADDRESS"))?;
    chain_id.parse().ok()
}

#[cfg(test)]
fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// The 8 network settings, which have no default.
#[cfg(test)]
const REQUIRED: [(&str, &str); 8] = [
    ("AVAIL_CLIENT_URL", "https://avail.example/rpc"),
    ("ETHEREUM_CLIENT_URL", "https://ethereum.example/rpc"),
    ("MERKLE_PROOF_SERVICE_URL", "https://merkle.example/api"),
    ("BEACONCHAIN_URL", "https://beacon.example"),
    (
        "VECTORX_CONTRACT_ADDRESS",
        "0x02993cdC11213985b9B13224f3aF289F03bf298d",
    ),
    ("CONTRACT_CHAIN_ID", "1"),
    ("AVAIL_CHAIN_NAME", "mainnet"),
    (
        "BRIDGE_CONTRACT_ADDRESS",
        "0x054fd961708D8E2B9c10a63F6157c74458889F0a",
    ),
];

/// The required settings and `more`. A name in `more` replaces the required one.
#[cfg(test)]
fn required_and(more: &[(&str, &str)]) -> HashMap<String, String> {
    let mut all = vars(&REQUIRED);
    all.extend(vars(more));
    all
}

#[cfg(test)]
fn error_of(vars: &HashMap<String, String>) -> String {
    match Config::from_vars(vars) {
        Ok(_) => "no error".to_owned(),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn test_missing_network_setting_is_an_error_that_names_it() {
    for (name, _) in REQUIRED {
        let mut missing = vars(&REQUIRED);
        missing.remove(name);
        assert_eq!(error_of(&missing), format!("{name} is not set"));

        let empty = required_and(&[(name, "")]);
        assert_eq!(error_of(&empty), format!("{name} is not set"));
    }
}

#[test]
fn test_bad_number_is_an_error_that_names_the_setting_and_not_the_value() {
    for name in [
        "MAX_CONCURRENT_REQUEST",
        "ETH_HEAD_CACHE_MAXAGE",
        "AVL_HEAD_CACHE_MAXAGE",
        "HEAD_CACHE_MAXAGE",
        "ETH_PROOF_CACHE_MAXAGE",
        "PROOF_CACHE_MAXAGE",
        "ETH_PROOF_FAILURE_CACHE_MAXAGE",
        "AVL_PROOF_CACHE_MAXAGE",
        "HELIOS_UPDATE_FREQUENCY",
        "VECTOR_UPDATE_FREQUENCY",
    ] {
        // A secret that was put into the wrong setting must not reach the log.
        let bad = required_and(&[(name, "K3Y-in-the-wrong-setting")]);
        assert_eq!(error_of(&bad), format!("{name} is not a valid number"));
    }
    // 70000 does not fit the type of this setting.
    let too_large = required_and(&[("ETH_HEAD_CACHE_MAXAGE", "70000")]);
    assert_eq!(
        error_of(&too_large),
        "ETH_HEAD_CACHE_MAXAGE is not a valid number"
    );
}

#[test]
fn test_one_error_names_every_bad_setting() {
    let mut bad = required_and(&[("HEAD_CACHE_MAXAGE", "sixty"), ("PROOF_CACHE_MAXAGE", "-1")]);
    bad.remove("AVAIL_CLIENT_URL");
    bad.remove("BEACONCHAIN_URL");
    assert_eq!(
        error_of(&bad),
        "AVAIL_CLIENT_URL is not set, BEACONCHAIN_URL is not set, \
         HEAD_CACHE_MAXAGE is not a valid number, PROOF_CACHE_MAXAGE is not a valid number"
    );
}

#[test]
fn test_unset_settings_get_the_defaults() {
    // An empty number counts as not set: `.env.example` lists every setting with an empty value.
    for input in [
        vars(&REQUIRED),
        required_and(&[
            ("ETH_HEAD_CACHE_MAXAGE", ""),
            ("MAX_CONCURRENT_REQUEST", ""),
        ]),
    ] {
        let (config, warnings) = Config::from_vars(&input).unwrap();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, "8080");
        assert_eq!(config.max_concurrent_request, 1024);
        assert_eq!(config.postgres_url, "localhost:5432");
        assert_eq!(config.postgres_db, "ui-indexer");
        assert_eq!(config.pg_username, "avail");
        assert_eq!(config.pg_password, "avail");
        assert_eq!(config.eth_head_cache_maxage, 240);
        assert_eq!(config.avl_head_cache_maxage, 600);
        assert_eq!(config.head_cache_maxage, 60);
        assert_eq!(config.eth_proof_cache_maxage, 172800);
        assert_eq!(config.proof_cache_maxage, 172800);
        assert_eq!(config.eth_proof_failure_cache_maxage, 5400);
        assert_eq!(config.avl_proof_cache_maxage, 172800);
        assert_eq!(config.helios_update_frequency, 3600);
        assert_eq!(config.vector_update_frequency, 360);
        assert!(config.chains.is_empty());
        assert_eq!(warnings, Vec::<String>::new());
    }
}

#[test]
fn test_set_values_are_read() {
    let input = required_and(&[
        ("HOST", "127.0.0.1"),
        ("PORT", "9000"),
        ("MAX_CONCURRENT_REQUEST", "1"),
        ("POSTGRES_URL", "db.example:6432"),
        ("POSTGRES_DB", "indexer"),
        ("PG_USERNAME", "user"),
        ("PG_PASSWORD", ""),
        ("ETH_HEAD_CACHE_MAXAGE", "2"),
        ("AVL_HEAD_CACHE_MAXAGE", "3"),
        ("HEAD_CACHE_MAXAGE", "4"),
        ("ETH_PROOF_CACHE_MAXAGE", "5"),
        ("PROOF_CACHE_MAXAGE", "6"),
        ("ETH_PROOF_FAILURE_CACHE_MAXAGE", "7"),
        ("AVL_PROOF_CACHE_MAXAGE", "8"),
        ("HELIOS_UPDATE_FREQUENCY", "9"),
        ("VECTOR_UPDATE_FREQUENCY", "10"),
    ]);
    let (config, _) = Config::from_vars(&input).unwrap();
    assert_eq!(config.avail_client_url, "https://avail.example/rpc");
    assert_eq!(config.ethereum_client_url, "https://ethereum.example/rpc");
    assert_eq!(
        config.merkle_proof_service_base_url,
        "https://merkle.example/api"
    );
    assert_eq!(config.beaconchain_base_url, "https://beacon.example");
    assert_eq!(
        config.contract_address,
        "0x02993cdC11213985b9B13224f3aF289F03bf298d"
    );
    assert_eq!(config.contract_chain_id, "1");
    assert_eq!(config.avail_chain_name, "mainnet");
    assert_eq!(
        config.bridge_contract_address,
        "0x054fd961708D8E2B9c10a63F6157c74458889F0a"
    );
    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, "9000");
    assert_eq!(config.max_concurrent_request, 1);
    assert_eq!(config.postgres_url, "db.example:6432");
    assert_eq!(config.postgres_db, "indexer");
    assert_eq!(config.pg_username, "user");
    // An empty database setting is used as it is, as before.
    assert_eq!(config.pg_password, "");
    assert_eq!(config.eth_head_cache_maxage, 2);
    assert_eq!(config.avl_head_cache_maxage, 3);
    assert_eq!(config.head_cache_maxage, 4);
    assert_eq!(config.eth_proof_cache_maxage, 5);
    assert_eq!(config.proof_cache_maxage, 6);
    assert_eq!(config.eth_proof_failure_cache_maxage, 7);
    assert_eq!(config.avl_proof_cache_maxage, 8);
    assert_eq!(config.helios_update_frequency, 9);
    assert_eq!(config.vector_update_frequency, 10);
}

#[cfg(test)]
fn chain_ids(config: &Config) -> Vec<u64> {
    config.chains.iter().map(|chain| chain.chain_id).collect()
}

// The names that the mainnet deployment sets (helm-values, 2026-11-20), with example values.
#[test]
fn test_mainnet_setting_names_load() {
    let address = "0x02993cdC11213985b9B13224f3aF289F03bf298d";
    let input = required_and(&[
        ("HOST", "0.0.0.0"),
        ("ETH_HEAD_CACHE_MAXAGE", "60"),
        ("AVL_HEAD_CACHE_MAXAGE", "120"),
        ("ETH_PROOF_FAILURE_CACHE_MAXAGE", "600"),
        ("HELIOS_UPDATE_FREQUENCY", "3600"),
        ("VECTOR_UPDATE_FREQUENCY", "360"),
        ("POSTGRES_URL", "db.example:5432"),
        ("POSTGRES_DB", "ui-indexer"),
        ("PG_USERNAME", "user"),
        ("PG_PASSWORD", "password"),
        ("CHAIN_1_RPC_URL", "https://chain-1.example/K3Y"),
        ("CHAIN_1_CONTRACT_ADDRESS", address),
        // The code does not support chain 9075, and it reads neither of the last two names.
        ("CHAIN_9075_RPC_URL", "https://chain-9075.example/K3Y"),
        ("CHAIN_9075_CONTRACT_ADDRESS", address),
        ("SLOT_MAPPING_CACHE_MAXAGE", "60"),
        ("BEACONCHAIN_API_KEY", "K3Y"),
    ]);
    let (config, warnings) = Config::from_vars(&input).unwrap();
    assert_eq!(chain_ids(&config), [1]);
    assert_eq!(
        config.chains[0].rpc_url.as_str(),
        "https://chain-1.example/K3Y"
    );
    assert_eq!(
        config.chains[0].contract_address,
        address.parse::<Address>().unwrap()
    );
    assert_eq!(
        warnings,
        [
            "CHAIN_9075_CONTRACT_ADDRESS is ignored, because chain 9075 is not supported",
            "CHAIN_9075_RPC_URL is ignored, because chain 9075 is not supported",
        ]
    );
}

// The chains that the Turing deployments set (helm-values, 2026-11-20).
#[test]
fn test_turing_chains_load() {
    let address = "0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96";
    let input = required_and(&[
        ("CHAIN_11155111_RPC_URL", "https://sepolia.example"),
        ("CHAIN_11155111_CONTRACT_ADDRESS", address),
        ("CHAIN_123_RPC_URL", "https://chain-123.example"),
        ("CHAIN_123_CONTRACT_ADDRESS", address),
        ("CHAIN_32657_RPC_URL", "localhost:8545"),
        ("CHAIN_32657_CONTRACT_ADDRESS", address),
    ]);
    let (config, warnings) = Config::from_vars(&input).unwrap();
    assert_eq!(chain_ids(&config), [123, 32657, 11155111]);
    // `localhost:<port>` without a scheme means plain HTTP, as before.
    assert_eq!(config.chains[1].rpc_url.as_str(), "http://localhost:8545/");
    assert_eq!(warnings, Vec::<String>::new());
}

#[test]
fn test_skipped_chain_gets_a_warning_without_the_value() {
    let address = "0xe542dB219a7e2b29C7AEaEAce242c9a2Cd528F96";
    let input = required_and(&[
        ("CHAIN_1_RPC_URL", "https://chain-1.example/K3Y"),
        ("CHAIN_123_CONTRACT_ADDRESS", address),
        ("CHAIN_17000_RPC_URL", "not a url K3Y"),
        ("CHAIN_17000_CONTRACT_ADDRESS", address),
        ("CHAIN_84532_RPC_URL", "https://chain-84532.example/K3Y"),
        ("CHAIN_84532_CONTRACT_ADDRESS", "K3Y-not-an-address"),
        ("CHAIN_421614_RPC_URL", "https://chain-421614.example"),
        ("CHAIN_421614_CONTRACT_ADDRESS", address),
    ]);
    let (config, warnings) = Config::from_vars(&input).unwrap();
    assert_eq!(chain_ids(&config), [421614]);
    assert_eq!(
        warnings,
        [
            "CHAIN_1_CONTRACT_ADDRESS is not set, skipping chain",
            "CHAIN_123_RPC_URL is not set, skipping chain",
            "CHAIN_84532_CONTRACT_ADDRESS is not a valid address, skipping chain",
            "CHAIN_17000_RPC_URL is not a valid URL, skipping chain",
        ]
    );
}
