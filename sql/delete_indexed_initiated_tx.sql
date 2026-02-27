DELETE FROM initiated_transactions
WHERE
-- Clean up initiate records when source tx is indexed
(tx_type = 'initiate' AND direction = 'EthAvail' AND EXISTS (
    SELECT 1 FROM bridge_event be
    WHERE be.source_transaction_hash = initiated_transactions.source_transaction_hash
))
OR (tx_type = 'initiate' AND direction = 'AvailEth' AND EXISTS (
    SELECT 1 FROM avail_indexer ai
    WHERE ai.ext_hash = initiated_transactions.source_transaction_hash
))
-- Clean up claim records when claim tx is indexed
OR (tx_type = 'claim' AND direction = 'AvailEth' AND EXISTS (
    SELECT 1 FROM bridge_event be
    WHERE be.message_id::text = initiated_transactions.message_id
      AND be.event_type = 'MessageReceived'
))
OR (tx_type = 'claim' AND direction = 'EthAvail' AND EXISTS (
    SELECT 1 FROM avail_execute_table aet
    WHERE aet.message_id::text = initiated_transactions.message_id
))
