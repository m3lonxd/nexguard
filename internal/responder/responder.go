package responder

import "nexguard/internal/transport"

type Responder interface {
	Respond(f transport.Finding) (*transport.ActionLog, error)
}

// CommandRunner is implemented by ExecRunner for real use and by a fake in
// tests, so unit tests never shell out to nft/ufw.
type CommandRunner interface {
	Run(name string, args ...string) (output string, err error)
}
