# NexGuard

NexGuard is an AI-assisted security monitoring tool for Linux servers, split into a
lightweight agent (`nexguard-agentd`) and a central panel/server (`nexguard-serverd`).
This first slice covers one full path end to end: the agent tails SSH auth logs,
detects brute-force login attempts, automatically blocks the offending IP (Tier A
response), and reports both the finding and the action it took back to the panel,
where they show up on a live dashboard.

Everything else (package/CVE scanning, file-integrity monitoring, rootkit scanning,
AI explanations, multi-server UI polish, packaging) is intentionally out of scope for
this slice.

## Build

```sh
cd /home/omarchy/nexguard
go build ./...
```

This produces no top-level binaries by default; build each command explicitly:

```sh
go build -o nexguard-serverd ./cmd/server
go build -o nexguard-agentd  ./cmd/agent
```

Run the test suite and static checks:

```sh
go vet ./...
go test ./...
gofmt -l .   # should print nothing
```

## Manual end-to-end test

This walks through the full slice: start the panel, enroll an agent against it,
feed it a synthetic SSH brute-force burst, and confirm the finding and the
resulting block action both show up through the panel's API.

1. **Start the server** (uses port 8842 locally, a scratch SQLite file so it
   doesn't touch any real data):

   ```sh
   go run ./cmd/server --addr :8842 --db /tmp/nexguard-test.db
   ```

2. **Enroll an agent** against it, in a second terminal. This registers a new
   server record with the panel and writes a config file containing the
   issued bearer token:

   ```sh
   go run ./cmd/agent --enroll http://localhost:8842 --config /tmp/nexguard-agent.yaml
   ```

3. **Build a fake auth log** with 6+ failed SSH attempts from one IP (above
   the default threshold of 5 within a 5 minute window):

   ```sh
   for i in $(seq 1 6); do
     echo "Jan  1 10:00:0$i myhost sshd[1234]: Failed password for root from 203.0.113.7 port 4000$i ssh2"
   done > /tmp/fake-auth.log
   ```

4. **Run the agent** against that file instead of the real system log, using
   the `--authlog` override:

   ```sh
   go run ./cmd/agent --config /tmp/nexguard-agent.yaml \
     --authlog /tmp/fake-auth.log \
     --audit-log /tmp/nexguard-actions.jsonl \
     --threshold 5 --window 5m
   ```

   The agent parses the burst, fires an `ssh_bruteforce` finding once the
   threshold is crossed, pushes it to the panel, and asks its responder to
   block `203.0.113.7`. In a sandbox without `nft` or `ufw` installed, the
   block attempt fails — this is expected and must not crash the agent; it
   is recorded as a `failed` action with a `reason`, both in
   `/tmp/nexguard-actions.jsonl` and on the panel.

5. **Verify via the panel API**:

   ```sh
   curl -s http://localhost:8842/api/v1/findings | jq
   curl -s http://localhost:8842/api/v1/actions  | jq
   ```

   The finding should show `type: "ssh_bruteforce"`, `ip: "203.0.113.7"` in
   its evidence, and `attempts: 6`. The action should reference that same
   finding via `finding_id` and show `action_type: "block_ip"` with
   `params.status` of `"applied"` (if a firewall backend is present) or
   `"failed"` (if not, as above) — either way, the agent process itself
   must exit cleanly rather than crashing.

6. Open `http://localhost:8842/` in a browser to see the same finding and
   action on the dashboard, pushed live over the `/api/v1/stream` WebSocket
   as they arrive.

## Security note

Phase 1 enrollment (`POST /api/v1/enroll`) is intentionally open/unauthenticated:
any client that can reach the panel can register a new agent and receive a
bearer token. This is acceptable for a trusted local network during this
slice but must be locked down (e.g. a one-time enrollment code, mTLS, or an
allowlist) before exposing the panel beyond a trusted network.
