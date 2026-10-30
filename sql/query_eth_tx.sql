SELECT t.message_id               AS "message_id!",
       t.sender                   AS "sender!",
       t.receiver                 AS "receiver!",
       t.amount                   AS "amount!",
       t.source_block_hash        AS "source_block_hash!",
       t.source_transaction_hash  AS "source_transaction_hash!",
       t.block_number             AS "source_block_height!",
       t.timestamp                AS "timestamp!",
       t.destination_block_height AS "destination_block_height?: i32",
       t.destination_tx_index     AS "destination_tx_index?: i32",
       COALESCE(
               CASE
                   WHEN t.status = 'in_progress' AND t.execute_id IS NULL THEN 'in_progress'::status
                   WHEN t.status = 'in_progress' AND t.execute_id IS NOT NULL THEN 'bridged'::status
                   ELSE t.status
                   END,
               'in_progress'::status
       ) ::status                 AS "final_status!: BridgeStatusEnum"
-- One row per message of this sender, with its successful execute if there is one. Only this
-- sender's messages are joined with executes, and avail_indexer is read by primary key for the
-- matches only.
FROM (SELECT DISTINCT ON (be.message_id) be.message_id,
                                          be.sender,
                                          be.receiver,
                                          be.amount,
                                          be.source_block_hash,
                                          be.source_transaction_hash,
                                          be.block_number,
                                          be.timestamp,
                                          be.status,
                                          ai.id           AS execute_id,
                                          ai.block_height AS destination_block_height,
                                          ai.ext_index    AS destination_tx_index
      FROM bridge_event be
               LEFT JOIN public.avail_execute_table AS aet
                         ON be.message_id = aet.message_id
               LEFT JOIN public.avail_indexer AS ai ON ai.id = aet.id AND ai.ext_success = $3
      WHERE be.sender = $1
        AND be.event_type = $2
      ORDER BY be.message_id, ai.id NULLS LAST) AS t
ORDER BY t.timestamp DESC
LIMIT 1000
