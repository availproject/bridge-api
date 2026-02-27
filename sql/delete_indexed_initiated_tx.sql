DELETE FROM initiated_transactions it
WHERE
-- Scope cleanup to the senders passed into the transactions query.
(it.sender = $1 OR it.sender = $2)
AND (
    -- Clean up initiate records when source tx is indexed.
    (it.tx_type = 'initiate' AND it.direction = 'EthAvail' AND EXISTS (
        SELECT 1 FROM bridge_event be
        WHERE be.source_transaction_hash = it.source_transaction_hash
    ))
    OR (it.tx_type = 'initiate' AND it.direction = 'AvailEth' AND EXISTS (
        SELECT 1 FROM avail_indexer ai
        WHERE ai.ext_hash = it.source_transaction_hash
    ))
    -- Clean up claim records when claim tx is indexed.
    OR (it.tx_type = 'claim' AND it.direction = 'AvailEth' AND EXISTS (
        SELECT 1 FROM bridge_event be
        WHERE be.message_id::text = it.message_id
          AND be.event_type = 'MessageReceived'
    ))
    OR (it.tx_type = 'claim' AND it.direction = 'EthAvail' AND EXISTS (
        SELECT 1 FROM avail_execute_table aet
        WHERE aet.message_id::text = it.message_id
    ))
)
