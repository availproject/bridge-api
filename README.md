# Bridge API

The bridge API is a REST API for fetching proofs from Avail's Kate RPC and Merkle proof service API to submit on Ethereum or
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

* Supported API versions on the server:

    * Request

      `GET /versions`

      ```bash
      # curl <endpoint URL>/versions
      curl http://localhost:8080/versions
      ```

    * Response

      ```json
      ["v1"]
      ```

### Liveness of the server

* To verify that the API is live, you can query the root like:

    * Request

      `GET /`

      ```bash
      # curl <endpoint URL>
      curl http://localhost:8080
      ```

    * Response

      ```json
      {"name":"Avail Bridge API"}
      ```

  * To get information of the bridge details:

      * Request

        `GET /v1/info`

        ```bash
        # curl <endpoint URL>
        curl http://localhost:8080/v1/info
        ```

      * Response

        ```json
        {
         "availChainName": "hex",
         "bridgeContractAddress": "0x1369A4C9391cF90D393b40fAeAD521b0F7019dc5",
         "vectorXChainId": "11155111",
         "vectorXContractAddress": "0x570f6a1936386a4e060C2Daebbd0b6f5C091e13f"
        }
        ```



### Get current Ethereum head

* To get the latest Ethereum block number, query:
    * Request
      `GET /v1/eth/head`

      ```bash
      # curl <endpoint URL>/v1/eth/head
      curl http://localhost:8080/v1/eth/head
      ```
        * Response

      ```json
      {
        "slot":4454752,
        "timestamp":1709191840,
        "timestampDiff":1716
      }
      ```

### Get current Avail head

* To get the latest Avail block number, query:
    * Request
      `GET /v1/avl/head`

      ```bash
      # curl <endpoint URL>/v1/avl/head
      curl http://localhost:8080/v1/avl/head
      ```
        * Response

      ```json
      {
        "data":{
          "end":512738,
          "start":488581
          }
      }
      ```

### Get SP1Vector head
* To get the latest Avail block stored on an SP1Vector contract instance, query:
    * Request
      `GET /v1/head/{chain_id}`

      ```bash
      # curl <endpoint URL>/v1/head/{chain_id}
      curl http://localhost:8080/v1/head/{chain_id}
      ```
        * Response

      ```json
      {
        "head": 123456
      }
      ```

### Generate Merkle Proof

* To generate a proof, simply query the `eth/proof` endpoint with the block hash and extrinsic index like (both are
  required):

    * Request

      `GET /v1/eth/proof/:blockhash?index=`

      ```bash
      # curl "<endpoint URL>/v1/eth/proof/<blockhash>?index=<tx_index>"
      curl "http://localhost:8080/v1/eth/proof/0x5bc7bd3a4793132007d6d0d9c55dc2ded2fe721a49bd771c1d290e6a3c6ec237?index=5"
      ```

      * Response

        ```json
        {
          "blobRoot": "0x511030804f9768c9d5c4826cdc7eba25ba0fd8e73ea32467e5fad547397620f8",
          "blockHash": "0x5bc7bd3a4793132007d6d0d9c55dc2ded2fe721a49bd771c1d290e6a3c6ec237",
          "bridgeRoot": "0xf6c807bc73a637957a61d620bd5e4ef8c7dd234e5fc96dfb6d6041bbe2947782",
          "dataRoot": "0x2179e18ee112b080794b40f2239d77041c715ad7392d9fce054b7c10eacd4ebc",
          "dataRootCommitment": "0x41cfe14b2e229cc5b4ee0cb7c3c909e1f78ae9e32f986e7496bfd4e007e06519",
          "dataRootIndex": 48,
          "dataRootProof": [
            "0x0395f21560a9ccc1f2aa972601250256fbdb20fd936e1723397ff8d5e4f07b5d",
            "0x1e91eb5ce2802373a583ce83898e8b4c1bb648e3c76bad87820a197b73b6d23b",
            "0xd49b33b5754aa6c9549e9677e4c646bd4e7d500a2ab9761cffff5363f4608ac7",
            "0x575858cb3bb948af2d8c4582310f951eb798281f71e913e044c6c415031f58a3",
            "0x353fe475ab9b0e00c3bfae8598fef61ac2921a7928b21ad45b6594c023611156",
            "0x4cb574d05c6606d2509ec6849e0cb53d04c5eead1cdbed4704018da938df5460",
            "0xd88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1",
            "0x87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"
            ],
            "leaf": "0xe17de7631392427460102691ba8a22adf5fb410548e50d6c636bf1f96840c3c3",
            "leafIndex": 0,
            "leafProof": [
              "0x00017cadd87ec12039f98d646afaa33ed843056ad12f5e971cc81be15d00c26f",
              "0xd046caabde74922f9d69e9fd33de6d3b9ee0f5c536183c4f4259f078afda538a"
            ],
            "message": {
            "destinationDomain": 2,
            "from": "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
            "id": 256491151949829,
            "message": {
              "fungibleToken": {
                "amount": 5000000000000000,
                "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000"
              }
            },
            "originDomain": 1,
            "to": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "rangeHash": "0x21c402a3ccf8df26cb720c6d2fb409f04c809adef7a9a852e463cca83588f4fb"
        }
        ```

### Generate Merkle Proof

* To generate a proof, simply query the `v1/proof` endpoint with the mandatory query params block hash, extrinsic index and chain id:

    * Request

      `GET /v1/proof/<chain_id>?block_hash=&index=`

      ```bash
      # curl "<endpoint URL>/v1/proof/<chain_id>?block_hash=<blockhash>&index=<tx_index>"
      curl "http://localhost:8080/v1/proof/11155111?block_hash=0x5bc7bd3a4793132007d6d0d9c55dc2ded2fe721a49bd771c1d290e6a3c6ec237&index=5"
      ```

        * Response

          ```json
          {
            "blobRoot": "0x511030804f9768c9d5c4826cdc7eba25ba0fd8e73ea32467e5fad547397620f8",
            "blockHash": "0x5bc7bd3a4793132007d6d0d9c55dc2ded2fe721a49bd771c1d290e6a3c6ec237",
            "bridgeRoot": "0xf6c807bc73a637957a61d620bd5e4ef8c7dd234e5fc96dfb6d6041bbe2947782",
            "dataRoot": "0x2179e18ee112b080794b40f2239d77041c715ad7392d9fce054b7c10eacd4ebc",
            "dataRootCommitment": "0x41cfe14b2e229cc5b4ee0cb7c3c909e1f78ae9e32f986e7496bfd4e007e06519",
            "dataRootIndex": 48,
            "dataRootProof": [
              "0x0395f21560a9ccc1f2aa972601250256fbdb20fd936e1723397ff8d5e4f07b5d",
              "0x1e91eb5ce2802373a583ce83898e8b4c1bb648e3c76bad87820a197b73b6d23b",
              "0xd49b33b5754aa6c9549e9677e4c646bd4e7d500a2ab9761cffff5363f4608ac7",
              "0x575858cb3bb948af2d8c4582310f951eb798281f71e913e044c6c415031f58a3",
              "0x353fe475ab9b0e00c3bfae8598fef61ac2921a7928b21ad45b6594c023611156",
              "0x4cb574d05c6606d2509ec6849e0cb53d04c5eead1cdbed4704018da938df5460",
              "0xd88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1",
              "0x87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"
              ],
              "leaf": "0xe17de7631392427460102691ba8a22adf5fb410548e50d6c636bf1f96840c3c3",
              "leafIndex": 0,
              "leafProof": [
                "0x00017cadd87ec12039f98d646afaa33ed843056ad12f5e971cc81be15d00c26f",
                "0xd046caabde74922f9d69e9fd33de6d3b9ee0f5c536183c4f4259f078afda538a"
              ],
              "message": {
              "destinationDomain": 2,
              "from": "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
              "id": 256491151949829,
              "message": {
                "fungibleToken": {
                  "amount": 5000000000000000,
                  "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000"
                }
              },
              "originDomain": 1,
              "to": "0x0000000000000000000000000000000000000000000000000000000000000000"
              },
              "rangeHash": "0x21c402a3ccf8df26cb720c6d2fb409f04c809adef7a9a852e463cca83588f4fb"
          }
          ```

### Get Account/Storage proofs

* To get a proof, simply query the `/v1/avl/proof/:message_id` endpoint with the message id:

  * Request

    `GET /v1/avl/proof/:block_hash/:messageId`

      ```bash
      # curl "<endpoint URL>/v1/avl/proof/<blockhash>/<messageId>"
      curl "http://localhost:8080/v1/avl/proof/0x7963d8403d137cb5560e2436df07c233d18030b5f3f0c61b85083e2a8f2b5e55/1"
      ```

      * Response

      ```json
        {
           "accountProof": [
              "0xf90211a04ea3386c3564d92c70c842f4fe40a382ab0c0915bd52f1cfdf515e7df40f6365a05fd188dd610941144f5367487b343528f30b6fe1713e14c489a925d31b76de8ea081a4596748d2119583d96af1f6459bfc4d4cf48e5cf9f4171bb0f15b54bfc705a0934bf30f9e4643c1e8cabd31b65867d5dce6702ff922d5d5f88edd77c16eddf8a020c236a887760702595f069baa5c20a5d7f7ff56e99e4f2291e6c383ec2f1376a0a4c5d6569cf6acb8b7b744bdb847ee84c7a250a05858f21c4b71e892e0f6368ca0431a25d2f4d04d92b7f663f91b65029bd2a443fdcd71d6a5d1cd2bad5f937da5a09d5da24c3c97ebd7ed4897206e30464414bdaf91fb633ef6e5aa61ec4573b829a0e1850f0a51e6f8fb4e7b7d0a592a478e4fd4f55132faad2e05c774f2c5bf3722a0e437d19bee3cdd31e6a54da59dd1730d20ad59b1e816ba304b0f8cf89fa62697a07c9058190b5603de7af44f45d2654832a5e5186db18b28514101f5df81287a27a08637a03272d24e7d380f3d68a38525d0348cce5fe90ae32f2b51149badd96f75a0d45f94f513a8918bafb074ac20f951e6ddd59cfa414550ea7af155ea7530e386a03dc457251a135a4002731a17ee72e722897a64509dd108eeb729bb1d9a84bf3ca0e1834ab71a27a983540fee14db56a40c26e3936db6b76d950a117acd5d2a03fea053388d24ffe072f62c6ed5dc8d8e286e167648a5bed4f9a1445df2b2581a589880",
              "0xf90211a05f1dfe6f285811ddc2b5c1b2e0b4c9715586274627a60885abf66fe60f58f39ea098709a8cac54a765fa8b09b12849171bc2aadece08d4d21e2631efb92e422a72a09456842fb2f41eeaad70f98549983ec28ac5cc97b2bacd325a341bf8fecbd3fda012f6579824d8706f219fab4e6209270b3c5a7f9b9b10434422173bee004ebf87a0cad660f5066719c1e57fa895b385aedb678d89843f93fa9d284137cce585d912a08aee33972b41bd2c81bb805877f91b5c720c518551071c8c7b7b5035fc855dcaa0fe78af4efca09613a5b166012ad59ce6450d8f612d872010b8cb2cfce5171e01a0ed34274b556d95bc83b368a313d81e2418c84435e094626f568294de2c6adda3a0c4a8516496de7bd739485f7f0ea764e5f1e64f18ea24d5c2662df9321ad476b0a0c3ac05b241ad4ce2e59c05d280a56cdcaa38b8d974d0086a517ea0e71f47dbbba0c786b94bc71965e950e2cddbc6dc3d20b9527f14ac6720dffd93531f58cbb2caa0db4936424a52afb5f811937e21c36dbfc115f36167f57ea0f0770ba5b2b01509a08bfc560bf436ebfd1b9b2a16b38c37fdef7b27b5c5facf3d8487034100e04da3a0d19c58734f31adc98c08131a3f441d4945c63a569d381265517fb270d149fcd9a0a49a515f1d226b9a55079dd09128e8d068ce4473fc2afc7ce83ca73b4a4aeca8a039f4a70c5da7a6f9a75ccfbfa4e4660f367d83ed133633a09d8d85f3b81619b080",
              "0xf90211a013013c8d88c90029dae1eb17e9fde9d31aa12a845f977d5b05edfbb836490ed1a08313217b9700aa20e3f2bca060da9c6986794e32e39ee8378c5fc090ea3900c4a0bb6f74f7517cc6d53e1ac28cda4b7492460eac8ad25dae2e6f5dd83054975f5aa06591f5961ce401397d1b7ca8ace8c514f0711029a4804afc5dff746535f4b310a0acb9ff577f6e255b1739bdca46b3fca567678334cef7a7c3459110d398117ca0a0ca52f676d720f2148ea17a8949d8456043eca88e500c0455de24bd5f97c4574ba043f8dbbd691453a0601664d5a35b89b7980c679924f93427d446ccb4b8f54bfba0429ee0cf4db61c968b343ade1502260068beaa87dc31e673c3abeaad60dbe7a5a03e27446763b24c289f918b1710dd069019fb95cd822997fb6fbc1db75ac8b0eca0fdf20b9898a99a2378bb653195060908595370eb56d905306ca1d1260d5c4120a0c63d1fb8a5be22724ea48117eab3b87f9a2ff76c6dec7f3568ddc16098f31b68a0e527b82ba67b4d9299c0e11f48362894ff615bf39e36ccde2d4e13b636262833a008b21c1e3dc4c5938833ed344842aff4a75297019736e1b66820a959d3092561a02bcb48ab6bf1b0b426008ab0919010b847473a3710806632bed77f05d10b2f5ca09b61c79db573dcc92d61a101051e2cffc43389cbffb39cba671fd5a706c26cd1a030051e73e7a062b2812459e8cd4c2db94c408f2dc706fc16ed632cda8707f3bd80",
              "0xf90211a007df9be996660f9f91495c59b998832068088ae9034c5b04639694168b9571e6a0aa1dc52398e74cf48729ec879a6ee91c2e73cc73c076f953dda4dfe580ff05e3a0afc1d0a6d1d8723d5c16d5b25673eb3f4d05ef1466612ee9182781bbe987611ea038064f5d9c62106631b05c606352db759e3b535cdafeafb16638c9515731a7cba06800f0958bb61b89dd4bb02eb3da4bf6c14ad00b4a48a66019b0e6d15cc84ee1a08c149b7166f15e51a524ee32ea212f60d6df6a800e01d4fa22ffede5a39ee9e5a093922185d4bdbe12d5e5c62194739038e89b01d67f476acc8865817ac7ed9008a016d39ae51fad6e0f060d8653d173460ed52a823010a29db6edbc042b21e78fbca0f2c153d9c2c2b50644bc8098925dbb3ed618fa7e82ebb94e40965b2c977b6811a01f01669c56000db9ac524e334dace75e9f082db5c95ed9075caacc99165abc76a04ced0f74f50c438075f4d18fe1a0bbafa324e4a5a0d5fb7865acb35c72533e4ba0c8053b16343a4f4dd43ab76abb1cac2f8e791fdb3fa9121014cf7a42151860d3a06961b3a4f6ca879e0377f734d66f930af3258e1492be0c693d395c84a311a644a0a38ea23af3ce3d1d5b485a5c264f9cffaabe184e362466de6bf6e634062f5548a062843d42cff1c276a0e11cc1c6921151b7e84b8de41a2834c0beac97f6a07de3a0609f8c69b1fc2754e2d08946285d80a5a319647acef900dd97a62d21258a035880",
              "0xf90211a0aec1c4685e2c3b64c256d10b3135ef48b013524839f8373dbd0bc0eac8d7ba1fa05ab97dd3b415869a2674d9dd1744abfb45de8dffc2c302b05c1336d40c80cf14a07ad83ef3d645503b9afcf48de32fb677beef8b637aa120e6624acea518eb5b3fa030775e5e8230f409c292e2d4033a7530f83656cb67148acc599d37f782f8ef8ba013f3d308779aeb8958a612b37a07807a1783b0f99e1e5f76303fb7c3c44d622ca06e7b7e9dcfc4c24c702aef326848015731a4e20f0d8a02a401197e99c62ca1d7a0ae60461c17040fd1475fceac5e5f5528d2b972b084b4d5413f8cfb41f1ac7075a029a319fc16340bb5889952869c0184a1fc1d0427aa488dd597909671c9b41b6ca03abb30bb5daf1a503a65f2e7979f61ed288f163937406758e2a44ed7a751d216a04e9cfefe88b368b66e1da951909d6e6ce639845c19690778f6e316c9dc902d52a0c7eb14d0cf6465626d7834f200810b009aeb7b13f384c096ebe3ec503b75f4faa0ad3c0d202e74be0f188316e4e466ae7fca89b6a20994b22747b2f95febf5a449a0692d63a3756a510f8467f7da09e97da406265b4201fa4fe3577cbb887045cd6ea093b71eb86d53ddf8d13df0e7c446867dbacf096455045a2bd9690c56a443b4c3a0e712c0b14d1130db6db7edd7a93af2fc1a06d2e5793c4e54dcacca98b4cc6997a0bcc85c28e9f209b9b419e66f87bce37fbb42ba8416880935275c377d2fcebcc180",
              "0xf90191a0deb916373640a76bb6056aa37e9d548908c92fb5d3ea1fc69a1c99ddeb40eb24a029b4cdce0d4f7eed71cf6f6d21f4d27ef510b3e36c7c67587e84a08b8b288de380a0cd92c24f26cec2802437f2f8e56cdd35e47ed3edc4c806540740f5bf83f1c5ffa0aadf083c80930dee9f09d295708b24f31d2f41f50e1442e32ecbf03eb5b4a707a0f5335f3280d3be255686e95e46a353a1562a8008919a0051a46fb3fcce7c53caa07f9373bba9b4111e6d4ef57fecd16526497cdeaceccdb26ae09c526b834c83c3a0d000e75b89a65aedb850451d369e3ac5bf4d7ff0d71ec5e837417c0eaf074135a0a994cad72a8a641c62979d6f94ea0087a14770876869de76ff0aba4c51b7cfc480a094b7d0ec3e0de0f4135fed0b225c1a5f09fd8660e37fa7ee3d47cdf774fe4940a06e2c53738e77dd7b3c06aada2fcd6035a8435f8edbd40e0e9856439024502a2fa000e7bef9cf8c6301c9d0aba5e61136a898292f1cbde8861987d0999358f5505f80a0c232ad4a9e338ea79c8f86fc6a83952f212b4477a031a3c24d98d5aac8ef1fac8080",
              "0xf87180808080a038eace52a35a1cb3ba4dfc5a7dd4fd884d999c017dd48546779e9b1ceee867f3a07564257a73fdfa4e290ad21fe914294174996ac87095b5730370371f5ea133e980808080a0d51dbe737bf6d8c5b89bcf7724074067d2a4986c4180a5016a8bebfbc92f56e1808080808080",
              "0xf8669d38b7b6c4749ee47ec3483ea3325831ccd2fbcbbbcf7cb559ed13d35a14b846f8440280a0927826564770fb917bb1bc72e196fcf2fe2601c838c744106d1691a9da45b795a0fc50d62823735da871a4b45630e8f4a5aef99c18855869762b05d4f7fac4a859"
           ],
           "storageProof": [
              "0xf90211a02b61c0a3f1012b0c3fe640d90daf8f756f30665e9763d97c2809e683f57418bca0ca985e3b14af8741416d7c735fcc856c510138e8a82edd8506e49d8cac71258ca0bfebf2d2da505708433ec9e6d7d6f5f5706b502435ad98b8429f04f497f1e79ca0481bcb4d57a33e6fdd2d824b3f0bea708c76f437b114d043da26a9b019220552a01e5139fa355fc9ab10b4901bb0a1aee4b97b21441f3a6c2ecccadd2009b6e34fa05806452c1672d430087e3aac3e49901fe6788e8d5e2db17140ed49d3e4a6e262a00bc15c11195738ae6967054b12acc80948f99d852b3a05b2572407c67e98dfaca028fa67ddfd82c094d593d0001f099cff4f5bdad51cf0d77f4e5d15243c23701fa06ddefc9d483203b04420fc19c1de59664c839a726edb7cd6d519f63444293567a0fa38292ed34577ba490dfb1335d9ee2871bf64a498d8af13eb665516bc122fc8a03b6f3c05d6c9151aa3f552d3088d12e80ab70d78ef046ddf4d311dc35fd89699a02bbf18d484d22ce32d8efb9ad5236ca770f34ca46093a062c9fd0c00fce179b1a093e4702951798f5331327b8a6a613307e12edc789dc1ddb21ba4ef185122cedda091b0434eedf92e47d68213d40c2ead10fb94f7ce34845d9b85ddc255a5586f98a0b6a8a018fe45d5a78c237915cdc4db38a151c2078e9fd72ed53481072e816366a0c4a7126e02988de7caae8abdd299cf6fbde0eb2adc9be75ded86e8ea8388dead80",
              "0xf90151a0401fa10b5959532f16179be0bd2506e7f849495298c2de8fd5b8c4d63b1f2c1ca01dcc18ed03ed3183fe26600b23afedbebdd947d6b5019cc010ea359e0234afe0a050030a57a0878bb51bbd0c62d3ba0c2b782ebc5d6ec012a7a1bd0f20917558b6a0db69566205faf59c73db049a04d81f63db7d2dbafbe66ed91557e511ed0938d780a0e6114e00cb6c2aa9cf632cb93e5ccad1b4c9af79c769950743a647fe829c602ca0bcb35466c5b4c32c509da47141cb7b9c3dddff0ebcd0ea050bad4d398e2fb25f808080a054876fae9e71b3585d4e83ee48c65b366f6f13a3c1b9e2749918145eabd1c46da004531fc338c340e676badc1a99cad6ece2da3d08945f806cb7063bf3343d35f48080a0c68fcd91600b226b6c847f28d2f6ca3f60c55b1009b26e59f4d1087bb5d6fcc0a06c5aec8aa331b1f04b26a06cb64c5a6d63616d717f236d31106751bbea0d666880",
              "0xf871a08eccb5e838d7d0699e06d85c472bb097d8012c44d790e5d15c5b8465c7abb88180a02581c4c4535083ecd9ea1a314216bbe948f27bccb2e997c7796a9eec8f4c3df0a0c453ceda114a9775f135a7a2687f75e753c6f814789528fb73bb8cb5dec7eac680808080808080808080808080",
              "0xf8429f31265685397ec9fa17535b5603e86e2b01a583b71373e1b2cbfac2a5bff58fa1a0eb70a047920b4aa1f3a418b52e455694d4e1a2362fd7fbcf16fe53d798311beb"
           ]
        }   
     ```

### Get bridge transactions

* Get bridge transactions:

    * Request

      `GET /v2/transactions?availAddress=0x1a985fdff5f6eee4afce1dc0f367ab925cdca57e7e8585329830fc3ce6ef4e7a&ethAddress=0x48e7e157cf873c15a5a6734ea37c000e1cb2383d`

      ```bash
      # curl <endpoint URL>/v2/transactions?ethAddress=<availAddress>&ethAddress=<ethAddress>
      curl localhost:8080/v2/transactions?availAddress=0x1a985fdff5f6eee4afce1dc0f367ab925cdca57e7e8585329830fc3ce6ef4e7a&ethAddress=0x48e7e157cf873c15a5a6734ea37c000e1cb2383d
      ```

    * Response

      ```json
      [
        {
          "amount": "230000000000000000000000",
          "destinationBlockNumber": 1815039,
          "direction": "EthAvail",
          "messageId": 1717,
          "receiver": "0xc2b6ddd8382bcb813753562adb3d30cda40369750401b195dbabc6ac9bce620c",
          "sender": "0xc1b2aff52877b4a23422f554f3d240be50ec80cf",
          "sourceBlockHash": "0x8de5e002e1508780075a27c94fd4ef802899fb8adf0fb6a91c054e20a7ba41fd",
          "sourceTransactionHash": "0x8900d0483699fde57a13451d86130b3632946a0883936f9fb831914f18f643fb",
          "status": "Bridged"
        },
        {
          "amount": "112659800000000000000000",
          "destinationBlockNumber": 1814712,
          "direction": "EthAvail",
          "messageId": 1714,
          "receiver": "0xc2b6ddd8382bcb813753562adb3d30cda40369750401b195dbabc6ac9bce620c",
          "sender": "0xc1b2aff52877b4a23422f554f3d240be50ec80cf",
          "sourceBlockHash": "0xd3b45a1add7316c98d5bb7386d350a785b71f1db7c980018546b54de3172c5b7",
          "sourceTransactionHash": "0xa4060c27091859b64b71e4f479830b95c6948d29e189a1af6b1b016db0f48be9",
          "status": "Bridged"
        }
      ]
      ```

### Map slot to Ethereum block number (Deprecated)

* To map Ethereum slot to a block number:

    * Request

      `GET /beacon/slot/:slot_number`

      ```bash
      # curl <endpoint URL>/beacon/slot/<slotNumber>
      curl http://localhost:8080/beacon/slot/4448512
      ```

    * Response

      ```json
      {
        "blockHash":"0x5282299b298fe1d7238f1a48aa0f5e7cc19ccbcdeeba020b610db78abeb0d52b",
        "blockNumber":5380093
      }
      ```


### Initiate transaction

* To mark transaction as initiated:

    * Request

      `POST /v2/transaction/:tx_hash`

      ```bash
      # curl <endpoint URL>/v2/transaction/<txHash>
      curl -X POST \
      http://localhost:8080/v2/transaction/0x03c6dbd3c24c3f85e05be26d79f2f676f7c7ef4709
      ```

### Examples of using bridge api 

*  We have prepared a set of examples written in Rust and Typescript to help you understand how to use bridge api. You can explore these examples by visiting our [code examples repository](https://github.com/availproject/avail-bridge-examples).
