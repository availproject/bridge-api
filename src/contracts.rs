use alloy::sol;

sol! {
    #[derive(Debug)]
    contract AvailBridge {
        function sendAVAIL(bytes32 recipient, uint256 amount) external;
        event MessageSent(address indexed from, bytes32 indexed to, uint256 messageId);
    }
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    SP1Vector,
    "src/abi/SP1Vector.json"
);
