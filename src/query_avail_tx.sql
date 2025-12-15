SELECT
    ai1.id as message_id,
    ai1.signature_address as sender,
    es.to as receiver,
    es.amount,
    ai1.block_hash as source_block_hash,
    ai1.ext_hash as source_transaction_hash,
    ai1.block_height,
    COALESCE(
            CASE
                WHEN aet.message_id IS NOT NULL THEN 'bridged'::status
                END,
            'in_progress'::status
    ) AS final_status
FROM avail_send_message_table es
         INNER JOIN public.avail_indexer AS ai1
                    ON ai1.id = es.id
         LEFT JOIN public.bridge_event AS aet
                   ON es.id = aet.message_id
         LEFT JOIN public.avail_indexer AS ai2
                   ON ai2.id = aet.message_id
WHERE ai1.signature_address = $1
  AND aet.event_type = $3
  AND ai1.ext_success = $4
  AND es.type = $2
ORDER BY es.id DESC
LIMIT 1000;