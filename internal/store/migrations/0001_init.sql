CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    enrolled_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    action_type TEXT NOT NULL,
    params_json TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL,
    reverted_at TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_server_id ON findings(server_id);
CREATE INDEX IF NOT EXISTS idx_actions_finding_id ON actions(finding_id);
