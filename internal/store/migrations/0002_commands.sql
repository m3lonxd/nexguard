CREATE TABLE IF NOT EXISTS commands (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    type TEXT NOT NULL,
    params_json TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    done_at TIMESTAMP NULL
);

CREATE INDEX IF NOT EXISTS idx_commands_server_id ON commands(server_id, created_at);
