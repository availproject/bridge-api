SELECT
    ai.id                              as message_id,
    COALESCE(ai.signature_address, '') AS "sender!",
    es.to                              AS "receiver!",
    COALESCE(es.amount, '0')::text     AS "amount!",
    ai.block_hash                      as source_block_hash,
    ai.ext_hash                        as source_transaction_hash,
    ai.block_height,
    ai.ext_index,
    COALESCE(
            CASE
                WHEN be.message_id IS NOT NULL THEN 'bridged'::status
                END,
            'in_progress'::status
    ) ::status                         AS "final_status!: BridgeStatusEnum"
FROM avail_send_message_table es
         INNER JOIN public.avail_indexer AS ai
                    ON ai.id = es.id
         LEFT JOIN public.bridge_event AS be
                   ON es.id = be.message_id
WHERE ai.signature_address = $1
  AND be.event_type = $3
  AND ai.ext_success = $4
  AND es.type = $2
ORDER BY es.id DESC
LIMIT 1000;