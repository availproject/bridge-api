SELECT
    es.message_id,
    es.sender,
    es.receiver,
    es.amount,
    es.source_block_hash,
    es.source_transaction_hash,
    ai.block_height,
    COALESCE(
            CASE
                WHEN es.status = 'in_progress' AND aet.message_id IS NULL THEN 'in_progress'::status
                WHEN es.status = 'in_progress' AND aet.message_id IS NOT NULL THEN 'bridged'::status
                ELSE es.status
                END,
            'in_progress'::status
    ) AS final_status

FROM bridge_event es
         LEFT JOIN public.avail_execute_table AS aet
                   ON es.message_id = aet.message_id
         INNER JOIN public.avail_indexer ai on ai.id = aet.id
WHERE es.sender = $1
  AND es.event_type = $2
ORDER BY es.message_id DESC limit 1000