package handlers

import "io"

// CommandHandler is the interface implemented by every recorder command.
type CommandHandler interface {
	Name() string
	Handle(args string, r RecorderContext, w io.Writer) error
}
