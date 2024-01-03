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
