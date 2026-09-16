-- Provision before enabling PostgreSQL sessions. Use a dedicated Trustee database.
-- The runtime role needs SELECT, INSERT, UPDATE, DELETE, not schema ownership.
CREATE TABLE IF NOT EXISTS kbs_protocol_session (
    key TEXT PRIMARY KEY,
    value BYTEA NOT NULL
);
