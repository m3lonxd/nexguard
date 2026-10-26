package collectors

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

type Collector interface {
	Start(ctx context.Context) (<-chan AuthEvent, error)
}

// AuthLogCollector tails SSH auth events. If FilePath is set it always tails
// that file (used for tests and systems without journald); otherwise it
// prefers journalctl, since that is the source of truth on most modern
// distros where /var/log/auth.log may not exist at all.
type AuthLogCollector struct {
	FilePath string
}

func (c *AuthLogCollector) Start(ctx context.Context) (<-chan AuthEvent, error) {
	out := make(chan AuthEvent, 64)
	if c.FilePath != "" {
		go c.tailFile(ctx, c.FilePath, out)
		return out, nil
	}
	if journalctlPath, err := exec.LookPath("journalctl"); err == nil {
		go c.runJournal(ctx, journalctlPath, out)
		return out, nil
	}
	go c.tailFile(ctx, "/var/log/auth.log", out)
	return out, nil
}

func (c *AuthLogCollector) runJournal(ctx context.Context, journalctlPath string, out chan<- AuthEvent) {
	defer close(out)
	cmd := exec.CommandContext(ctx, journalctlPath, "-f", "-u", "ssh", "--no-pager", "-o", "cat")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("collectors: journalctl stdout pipe: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("collectors: journalctl start: %v", err)
		return
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if ev, ok := ParseAuthLine(scanner.Text()); ok {
			select {
			case out <- *ev:
			case <-ctx.Done():
				_ = cmd.Wait()
				return
			}
		}
	}
	_ = cmd.Wait()
}

func (c *AuthLogCollector) tailFile(ctx context.Context, path string, out chan<- AuthEvent) {
	defer close(out)
	f, err := os.Open(path)
	if err != nil {
		log.Printf("collectors: cannot open %s: %v", path, err)
		return
	}
	defer f.Close()
	reader := bufio.NewReader(f)

	emit := func() bool {
		for {
			line, err := reader.ReadString('\n')
			if line != "" {
				if ev, ok := ParseAuthLine(strings.TrimRight(line, "\r\n")); ok {
					select {
					case out <- *ev:
					case <-ctx.Done():
						return false
					}
				}
			}
			if err != nil {
				return true
			}
		}
	}
	if !emit() {
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("collectors: fsnotify unavailable (%v), falling back to polling", err)
		c.pollFile(ctx, emit)
		return
	}
	defer watcher.Close()
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		log.Printf("collectors: watch dir failed (%v), falling back to polling", err)
		c.pollFile(ctx, emit)
		return
	}

	target := filepath.Clean(path)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(ev.Name) == target && ev.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if !emit() {
					return
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("collectors: watcher error: %v", err)
		}
	}
}

func (c *AuthLogCollector) pollFile(ctx context.Context, emit func() bool) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !emit() {
				return
			}
		}
	}
}
