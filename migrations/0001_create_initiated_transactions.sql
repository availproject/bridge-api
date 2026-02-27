CREATE TABLE IF NOT EXISTS initiated_transactions (
    source_transaction_hash TEXT PRIMARY KEY,
    direction TEXT NOT NULL,
    message_id TEXT NOT NULL DEFAULT '0',
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    amount TEXT NOT NULL,
    source_block_hash TEXT NOT NULL,
    source_block_number INTEGER NOT NULL,
    source_tx_index INTEGER,
    timestamp BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_initiated_tx_sender ON initiated_transactions (sender);
ALTER TABLE initiated_transactions ADD COLUMN IF NOT EXISTS tx_type TEXT NOT NULL DEFAULT 'initiate';
