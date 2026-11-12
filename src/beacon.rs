use alloy::primitives::B256;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Root {
    pub data: Data,
}

#[derive(Debug, Deserialize)]
pub struct Data {
    pub message: Message,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub slot: String,
    pub body: MessageBody,
}

#[derive(Debug, Deserialize)]
pub struct MessageBody {
    /// Present before the Gloas fork.
    pub execution_payload: Option<ExecutionPayload>,
    /// Present from the Gloas fork, which replaced the payload with a builder's bid.
    pub signed_execution_payload_bid: Option<SignedExecutionPayloadBid>,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionPayload {
    pub block_number: String,
    pub block_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct SignedExecutionPayloadBid {
    pub message: ExecutionPayloadBid,
}

#[derive(Debug, Deserialize)]
pub struct ExecutionPayloadBid {
    pub parent_block_hash: B256,
}

/// The execution block whose state root the light client stores for a beacon slot.
#[derive(Debug, PartialEq)]
pub enum ExecutionBlock {
    Known {
        number: u64,
        hash: B256,
    },
    /// From Gloas the beacon block names the block only by hash, so its number must be looked up.
    ByHash(B256),
}

impl MessageBody {
    pub fn execution_block(&self) -> anyhow::Result<ExecutionBlock> {
        match (&self.execution_payload, &self.signed_execution_payload_bid) {
            (Some(payload), _) => Ok(ExecutionBlock::Known {
                number: payload.block_number.parse()?,
                hash: payload.block_hash.parse()?,
            }),
            // From Gloas the light client stores the state root of the bid's parent block, not of
            // the bid's own block (checked against Vector ExecutionStateRoots on Turing and Hex).
            (None, Some(bid)) => Ok(ExecutionBlock::ByHash(bid.message.parent_block_hash)),
            (None, None) => Err(anyhow::anyhow!(
                "beacon block has neither an execution payload nor a payload bid"
            )),
        }
    }
}

#[test]
fn test_pre_gloas_beacon_block_maps_to_execution_payload() {
    // Sepolia slot 11296672 (Fulu), trimmed to the fields the task reads.
    let root: Root = serde_json::from_str(
        r#"{"version":"fulu","data":{"message":{"slot":"11296672","body":{"execution_payload":{"block_number":"11856241","block_hash":"0x2963a21ef9ad725acdf867b6f04f1e2f6635c4ebecc36c72f15f1ea631ce97ca"}}}}}"#,
    )
    .unwrap();
    assert_eq!(
        root.data.message.body.execution_block().unwrap(),
        ExecutionBlock::Known {
            number: 11856241,
            hash: "0x2963a21ef9ad725acdf867b6f04f1e2f6635c4ebecc36c72f15f1ea631ce97ca"
                .parse()
                .unwrap(),
        }
    );
}

#[test]
fn test_gloas_beacon_block_maps_to_bid_parent_block() {
    // Sepolia slot 11337920 (Gloas), trimmed to the fields the task reads. Avail stored the state
    // root of block 11897272 for this slot, which is the bid's parent block, not its own block.
    let root: Root = serde_json::from_str(
        r#"{"version":"gloas","data":{"message":{"slot":"11337920","body":{"signed_execution_payload_bid":{"message":{"parent_block_hash":"0x2929e926e84142c0744f26dca3a1d5344a5c1b6e41e9628eb15eb70839d13af8","block_hash":"0x7a484bf89906cd90e43b7fd8416abd5101247835a29dd545848e14e549dec534"}}}}}}"#,
    )
    .unwrap();
    assert_eq!(
        root.data.message.body.execution_block().unwrap(),
        ExecutionBlock::ByHash(
            "0x2929e926e84142c0744f26dca3a1d5344a5c1b6e41e9628eb15eb70839d13af8"
                .parse()
                .unwrap()
        )
    );
}
