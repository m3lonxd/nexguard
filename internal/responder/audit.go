package responder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"nexguard/internal/transport"
)

// auditMu serializes writes to the (typically single) audit log file across
// goroutines, since TTL-triggered unblocks run on their own goroutine.
var auditMu sync.Mutex

// appendAuditLog appends one JSON line per block/unblock action to path,
// independent of whether the panel push succeeds, so there's always a local
// trail even when the network is down. An empty path disables the audit log.
func appendAuditLog(path string, action transport.ActionLog) error {
	if path == "" {
		return nil
	}
	auditMu.Lock()
	defer auditMu.Unlock()

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("audit log mkdir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(action)
}
