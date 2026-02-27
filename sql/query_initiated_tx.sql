SELECT source_transaction_hash, direction, message_id, sender, receiver,
       amount, source_block_hash, source_block_number, source_tx_index, timestamp, tx_type
FROM initiated_transactions it
WHERE tx_type = 'initiate'
  AND (it.sender = $1 OR it.sender = $2)
  AND NOT EXISTS (
    SELECT 1 FROM bridge_event be
    WHERE be.source_transaction_hash = it.source_transaction_hash
      AND it.direction = 'EthAvail'
  )
  AND NOT EXISTS (
    SELECT 1 FROM avail_indexer ai
    WHERE ai.ext_hash = it.source_transaction_hash
      AND it.direction = 'AvailEth'
  )
ORDER BY it.timestamp DESC
LIMIT 100
