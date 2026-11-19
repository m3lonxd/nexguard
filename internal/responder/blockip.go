package responder

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nexguard/internal/transport"
)

const DefaultTTL = time.Hour

// BlockIP implements the Tier A "blockip" responder: a low-risk, reversible
// action applied automatically on an ssh_bruteforce Finding. It also serves
// manual block/unblock commands from the panel and honours an allowlist.
// All methods are safe for concurrent use (the detector loop, the panel
// command loop and TTL timers call it from different goroutines).
type BlockIP struct {
	Runner    CommandRunner
	LookPath  func(file string) (string, error)
	TTL       time.Duration
	AuditPath string
	// Publish, if set, is called with every block/unblock ActionLog so the
	// caller can push it to the panel over internal/transport without this
	// package needing to know about server URLs or tokens.
	Publish func(transport.ActionLog)

	mu        sync.Mutex
	active    map[string]*activeBlock
	allow     map[string]bool
	autoTypes map[string]bool
}

type activeBlock struct {
	backend, ruleRef string
	action           transport.ActionLog
	timer            *time.Timer
}

// ErrNotBlocked is returned by Unblock for an ip this agent has no live rule for.
var ErrNotBlocked = errors.New("bu ip için etkin engel yok")

func NewBlockIP(runner CommandRunner, auditPath string, ttl time.Duration) *BlockIP {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &BlockIP{
		Runner:    runner,
		LookPath:  exec.LookPath,
		TTL:       ttl,
		AuditPath: auditPath,
		active:    map[string]*activeBlock{},
		allow:     map[string]bool{},
		autoTypes: map[string]bool{"ssh_bruteforce": true},
	}
}

func (b *BlockIP) init() {
	if b.active == nil {
		b.active = map[string]*activeBlock{}
	}
	if b.allow == nil {
		b.allow = map[string]bool{}
	}
	if b.autoTypes == nil {
		b.autoTypes = map[string]bool{"ssh_bruteforce": true}
	}
}

// SetAutoBlock turns automatic blocking on or off for a finding type
// (e.g. "honeypot_ssh"); ssh_bruteforce is on by default.
func (b *BlockIP) SetAutoBlock(findingType string, on bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	b.autoTypes[findingType] = on
}

// SetAllow replaces the allowlist. Allowlisted addresses are never blocked
// automatically or manually.
func (b *BlockIP) SetAllow(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.allow = map[string]bool{}
	for _, ip := range ips {
		b.allow[ip] = true
	}
}

func (b *BlockIP) Allowed(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allow[ip]
}

// Active lists the addresses this agent currently holds a rule for.
func (b *BlockIP) Active() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.active))
	for ip := range b.active {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (b *BlockIP) Respond(f transport.Finding) (*transport.ActionLog, error) {
	b.mu.Lock()
	b.init()
	auto := b.autoTypes[f.Type]
	b.mu.Unlock()
	if !auto {
		return nil, nil
	}
	ip, _ := f.Evidence["ip"].(string)
	return b.apply(ip, f.ID, "A", b.TTL, nil)
}

// Manual blocks ip on an operator's request; ref is the panel command id and
// is recorded in the action params.
func (b *BlockIP) Manual(ip string, ttl time.Duration, ref string) (*transport.ActionLog, error) {
	if ttl <= 0 {
		ttl = b.TTL
	}
	return b.apply(ip, "", "manual", ttl, map[string]any{"command": ref})
}

func (b *BlockIP) apply(ip, findingID, tier string, ttl time.Duration, extra map[string]any) (*transport.ActionLog, error) {
	action := transport.ActionLog{
		ID:         transport.NewID(),
		FindingID:  findingID,
		Tier:       tier,
		ActionType: "block_ip",
		AppliedAt:  time.Now().UTC(),
	}
	params := func(m map[string]any) map[string]any {
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if ip == "" {
		action.Params = params(map[string]any{"status": "skipped", "reason": "finding has no ip in evidence"})
		return b.finish(action)
	}
	// Defense in depth: a real sshd log can't forge this field (it comes from
	// the kernel's accept()ed socket), but we never want an unvalidated string
	// reaching an exec.Command argument list for a firewall rule either way.
	if net.ParseIP(ip) == nil {
		action.Params = params(map[string]any{"status": "skipped", "ip": ip, "reason": "invalid ip format"})
		return b.finish(action)
	}

	b.mu.Lock()
	b.init()
	if b.allow[ip] {
		b.mu.Unlock()
		action.Params = params(map[string]any{"status": "skipped", "ip": ip, "reason": "allowlisted"})
		return b.finish(action)
	}
	if _, dup := b.active[ip]; dup {
		b.mu.Unlock()
		action.Params = params(map[string]any{"status": "skipped", "ip": ip, "reason": "already blocked"})
		return b.finish(action)
	}
	// placeholder so a concurrent call for the same ip sees it as taken
	ab := &activeBlock{action: action}
	b.active[ip] = ab
	b.mu.Unlock()

	backend, ruleRef, err := b.block(ip, action.ID)
	if err != nil {
		b.mu.Lock()
		delete(b.active, ip)
		b.mu.Unlock()
		action.Params = params(map[string]any{"status": "failed", "ip": ip, "reason": err.Error()})
		return b.finish(action)
	}

	action.Params = params(map[string]any{
		"status":  "applied",
		"ip":      ip,
		"backend": backend,
		"rule":    ruleRef,
		"ttl":     ttl.String(),
	})
	b.mu.Lock()
	ab.backend, ab.ruleRef, ab.action = backend, ruleRef, action
	ab.timer = time.AfterFunc(ttl, func() { b.expire(ip, ab) })
	b.mu.Unlock()
	return b.finish(action)
}

// expire runs when a block's TTL elapses; it is a no-op if the block was
// already removed manually.
func (b *BlockIP) expire(ip string, ab *activeBlock) {
	b.mu.Lock()
	if b.active[ip] != ab {
		b.mu.Unlock()
		return
	}
	delete(b.active, ip)
	b.mu.Unlock()
	b.unblock(ip, ab.backend, ab.ruleRef, ab.action)
}

// Unblock removes this agent's live rule for ip before its TTL.
func (b *BlockIP) Unblock(ip string) (*transport.ActionLog, error) {
	b.mu.Lock()
	ab := b.active[ip]
	if ab == nil || ab.timer == nil {
		b.mu.Unlock()
		return nil, ErrNotBlocked
	}
	ab.timer.Stop()
	delete(b.active, ip)
	b.mu.Unlock()
	return b.unblock(ip, ab.backend, ab.ruleRef, ab.action)
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

func (b *BlockIP) unblock(ip, backend, ruleRef string, original transport.ActionLog) (*transport.ActionLog, error) {
	var err error
	switch backend {
	case "nft":
		err = b.unblockWithNft(ruleRef)
	case "ufw":
		err = b.unblockWithUfw(ip)
	default:
		return nil, fmt.Errorf("unknown backend %q", backend)
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
	out, ferr := b.finish(reverted)
	if err != nil {
		return out, err
	}
	return out, ferr
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
