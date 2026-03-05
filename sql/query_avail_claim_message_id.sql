SELECT aet.message_id::text
FROM avail_execute_table aet
JOIN avail_indexer ai ON ai.id = aet.id
WHERE ai.ext_hash = $1
LIMIT 1
