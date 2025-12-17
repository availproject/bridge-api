INSERT INTO bridge_event (
    message_id,
    event_type,
    status,
    sender,
    receiver,
    amount,
    source_block_hash,
    block_number,
    source_transaction_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)