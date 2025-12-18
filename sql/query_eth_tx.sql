SELECT be.message_id,
       be.sender,
       be.receiver,
       be.amount,
       be.source_block_hash,
       be.source_transaction_hash,
       be.block_number              as source_block_height,
       ai.block_height              as "destination_block_height?: i32",
       ai.ext_index                 as "destination_tx_index?: i32",
       COALESCE(
               CASE
                   WHEN be.status = 'in_progress' AND aet.message_id IS NULL THEN 'in_progress'::status
                   WHEN be.status = 'in_progress' AND aet.message_id IS NOT NULL THEN 'bridged'::status
                   ELSE be.status
                   END,
               'in_progress'::status
       ) ::status AS "final_status!: BridgeStatusEnum"
FROM bridge_event be
         LEFT JOIN public.avail_execute_table AS aet
                   ON be.message_id = aet.message_id
         LEFT JOIN public.avail_indexer AS ai on ai.id = aet.id
WHERE be.sender = $1
  AND be.event_type = $2
ORDER BY be.message_id DESC
limit 1000