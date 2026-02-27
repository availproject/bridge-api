SELECT EXISTS(SELECT 1 FROM initiated_transactions WHERE source_block_number = $1 AND source_tx_index = $2)
