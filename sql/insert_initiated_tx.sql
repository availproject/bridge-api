INSERT INTO initiated_transactions
    (source_transaction_hash, direction, message_id, sender, receiver, amount,
     source_block_hash, source_block_number, source_tx_index, timestamp, tx_type)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (source_transaction_hash) DO NOTHING
