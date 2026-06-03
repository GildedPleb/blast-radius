package daemon

import "github.com/GildedPleb/blast-radius/internal/daemon/handlers"

// DaemonContext is the narrow interface exposed to command handlers.
// This is a type alias to the canonical definition in the handlers package
// (avoids import cycles while letting daemon code refer to daemon.DaemonContext
// ergonomically). See internal/daemon/handlers/handlers.go for the real
// interface and docs.
type DaemonContext = handlers.DaemonContext
