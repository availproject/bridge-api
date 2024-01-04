# Bridge API
The bridge API is a REST API for fetching proofs from Avail's Kate RPC and Succinct API to submit on Ethereum or
any off-chain proof verification.

## Deploying the bridge API
* Create an `.env` file according to the `.env.example`
* To build the service:
```bash
# for developing, make a debug build
cargo build
# and run it!
cargo run
```
* Or instead, make release builds for production:
```bash
cargo run --release
# you can use maxperf to optimize for runtime performance:
cargo run --profile maxperf
# you can use RUSTFLAGS to use CPU-native optimizations:
RUSTFLAGS="-C target-cpu=native" cargo run --profile maxperf
```

## Usage
* The bridge API operates on the 8080 port by default (can be configured).
* To generate a proof, simply query the `/proof` endpoint with the block hash and extrinsic index like:
```bash
# curl "<endpoint URL>/proof/<blockhash>?index=<tx_index>"
curl "http://localhost:8080/proof/0x021134e8a6c9eebefce062d19db3a0cbca0eacb8bd44d6a6cd19cc39d2e6c02b?index=2"
```
