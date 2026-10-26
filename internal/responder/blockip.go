package responder

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"nexguard/internal/transport"
)

const DefaultTTL = time.Hour

// BlockIP implements the Tier A "blockip" responder: a low-risk, reversible
// action applied automatically on an ssh_bruteforce Finding.
type BlockIP struct {
	Runner    CommandRunner
	LookPath  func(file string) (string, error)
	TTL       time.Duration
	AuditPath string
	// Publish, if set, is called with every block/unblock ActionLog so the
	// caller can push it to the panel over internal/transport without this
	// package needing to know about server URLs or tokens.
	Publish func(transport.ActionLog)
}

func NewBlockIP(runner CommandRunner, auditPath string, ttl time.Duration) *BlockIP {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &BlockIP{
		Runner:    runner,
		LookPath:  exec.LookPath,
		TTL:       ttl,
		AuditPath: auditPath,
	}
}

func (b *BlockIP) Respond(f transport.Finding) (*transport.ActionLog, error) {
	if f.Type != "ssh_bruteforce" {
		return nil, nil
	}
	ip, _ := f.Evidence["ip"].(string)
	action := transport.ActionLog{
		ID:         transport.NewID(),
		FindingID:  f.ID,
		Tier:       "A",
		ActionType: "block_ip",
		AppliedAt:  time.Now().UTC(),
	}
	if ip == "" {
		action.Params = map[string]any{"status": "skipped", "reason": "finding has no ip in evidence"}
		return b.finish(action)
	}
	// Defense in depth: a real sshd log can't forge this field (it comes from
	// the kernel's accept()ed socket), but we never want an unvalidated string
	// reaching an exec.Command argument list for a firewall rule either way.
	if net.ParseIP(ip) == nil {
		action.Params = map[string]any{"status": "skipped", "ip": ip, "reason": "invalid ip format"}
		return b.finish(action)
	}

	backend, ruleRef, err := b.block(ip, action.ID)
	if err != nil {
		action.Params = map[string]any{"status": "failed", "ip": ip, "reason": err.Error()}
		return b.finish(action)
	}

	action.Params = map[string]any{
		"status":  "applied",
		"ip":      ip,
		"backend": backend,
		"rule":    ruleRef,
		"ttl":     b.TTL.String(),
	}
	time.AfterFunc(b.TTL, func() { b.unblock(ip, backend, ruleRef, action) })
	return b.finish(action)
}

func (b *BlockIP) finish(action transport.ActionLog) (*transport.ActionLog, error) {
	if err := appendAuditLog(b.AuditPath, action); err != nil {
		return nil, err
	}
	if b.Publish != nil {
		b.Publish(action)
	}
	return &action, nil
}

// block tries nftables first since it's the modern default on current
// distros, then falls back to ufw; either missing backend or a missing
// filter/input chain is logged and passed through rather than panicking.
func (b *BlockIP) block(ip, tag string) (backend, ruleRef string, err error) {
	lookPath := b.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	var nftErr, ufwErr error
	if _, lookErr := lookPath("nft"); lookErr != nil {
		nftErr = lookErr
	} else if ref, blockErr := b.blockWithNft(ip, tag); blockErr != nil {
		nftErr = blockErr
	} else {
		return "nft", ref, nil
	}

	if _, lookErr := lookPath("ufw"); lookErr != nil {
		ufwErr = lookErr
	} else if blockErr := b.blockWithUfw(ip); blockErr != nil {
		ufwErr = blockErr
	} else {
		return "ufw", ip, nil
	}

	return "", "", fmt.Errorf("no usable firewall backend (nft: %v; ufw: %v)", nftErr, ufwErr)
}

func (b *BlockIP) blockWithNft(ip, tag string) (string, error) {
	if _, err := b.Runner.Run("nft", "list", "chain", "inet", "filter", "input"); err != nil {
		return "", fmt.Errorf("inet filter input chain unavailable: %w", err)
	}
	comment := "nexguard-" + tag
	// nft is invoked without a shell, but its CLI grammar still requires the
	// literal quote characters around a string attribute like comment, so we
	// add them ourselves instead of relying on shell quoting that isn't there.
	if _, err := b.Runner.Run("nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop", "comment", strconv.Quote(comment)); err != nil {
		return "", err
	}
	return comment, nil
}

func (b *BlockIP) blockWithUfw(ip string) error {
	_, err := b.Runner.Run("ufw", "insert", "1", "deny", "from", ip)
	return err
}

func (b *BlockIP) unblock(ip, backend, ruleRef string, original transport.ActionLog) {
	var err error
	switch backend {
	case "nft":
		err = b.unblockWithNft(ruleRef)
	case "ufw":
		err = b.unblockWithUfw(ip)
	default:
		return
	}

	revertedAt := time.Now().UTC()
	reverted := original
	reverted.RevertedAt = &revertedAt
	params := map[string]any{"ip": ip, "backend": backend}
	if err != nil {
		params["status"] = "revert_failed"
		params["reason"] = err.Error()
	} else {
		params["status"] = "reverted"
	}
	reverted.Params = params
	_, _ = b.finish(reverted)
}

func (b *BlockIP) unblockWithNft(comment string) error {
	out, err := b.Runner.Run("nft", "-a", "list", "chain", "inet", "filter", "input")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, comment) {
			continue
		}
		idx := strings.LastIndex(line, "# handle ")
		if idx == -1 {
			continue
		}
		handle := strings.TrimSpace(line[idx+len("# handle "):])
		_, err := b.Runner.Run("nft", "delete", "rule", "inet", "filter", "input", "handle", handle)
		return err
	}
	return errors.New("rule not found, may have already been removed")
}

func (b *BlockIP) unblockWithUfw(ip string) error {
	_, err := b.Runner.Run("ufw", "delete", "deny", "from", ip)
	return err
}
