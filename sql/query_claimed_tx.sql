SELECT message_id, source_transaction_hash, source_block_number, source_tx_index
FROM initiated_transactions
WHERE tx_type = 'claim'
  AND message_id = ANY($1)
  AND (sender = $2 OR sender = $3)
