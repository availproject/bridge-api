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

### Liveness of the server

* To verify that the API is live, you can query the root like:

  * Request

    `GET /`

    ```bash
    # curl <endpoint URL>
    curl http://localhost:8080
    ```

  * Response

    ```bash
    # should return:
    {"name":"Avail Bridge API"}
    ```

### Generate Merkle Proof

* To generate a proof, simply query the `eth/proof` endpoint with the block hash and extrinsic index like (both are
required):

  * Request

    `GET /eth/proof/:blockhash?index=`

    ```bash
    # curl "<endpoint URL>/eth/proof/<blockhash>?index=<tx_index>"
    curl "http://localhost:8080/eth/proof/0xf53613fa06b6b7f9dc5e4cf5f2849affc94e19d8a9e8999207ece01175c988ed?index=1"
    ```

  * Response

    ```bash
    # should return:
    {
        "blobRoot": "0xaa4246713da25ab816ee6a00f3a523f48ce7b711120a7c3cf00e8851b9c99df2",
        "blockHash": "0xf53613fa06b6b7f9dc5e4cf5f2849affc94e19d8a9e8999207ece01175c988ed",
        "bridgeRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "dataRoot": "0x19b8a7551400209233c46f6d98abbd88c08e2d3f53a4cb9dfd5c6f3746ff53e5",
        "dataRootCommitment": "0x2ced6477d2b72909f36c9e88e32d33e33fb14526c0e3ed8c3a30a195f637e739",
        "dataRootIndex": 174,
        "dataRootProof": [
            "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5",
            "0x51f84e7279cdf6acb81af77aec64f618f71029b7d9c6d37c035c37134e517af2",
            "0x69c8458dd62d27ea9abd40586ce53e5220d43b626c27f76468a57e94347f0d6b",
            "0x5a021e65ea5c6b76469b68db28c7a390836e22c21c6f95cdef4d3408eb6b8050",
            "0xf1f603a14a615fa262f91fa788be910a2347429cba6a39d9d2781190a92cd3bb",
            "0x83aeb54660d9c6158085a50947e76e4ac01c95fd9b30e6d3bc865810ba6e73c4",
            "0xd88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1",
            "0x7b9b465d4b6271ac97a54fcd2b74423c9150463e6c90b6b609500d696b9ae394"
        ],
        "leaf": "0x6aaf64fab0bd05b12cd95b298ce0bf1bdda0f385b81578b60f8242cdb5d1983e",
        "leafIndex": 0,
        "leafProof": [],
        "rangeHash": "0x4b49a4b090404b1e83797cb77286f91a728a4d9ace03f2855025ccf7523ed720"
    }
    ```
