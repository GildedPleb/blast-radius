# Phase 0: Foundations & Core Architecture

**Status:** Completed  
**Date:** 2026-05-19

## Objectives

Establish the foundational Go binary as a secure, singleton, queryable daemon with:
- Clean separation of concerns
- Zero secret material in any persisted state
- Professional project structure
- Testable invariants

## Exit Criteria (All Met)

- [x] `blastradius status` works cleanly (auto-starts daemon when needed)
- [x] `blastradius stop` (or `halt`) gracefully shuts down the running daemon
- [x] Daemon starts, binds Unix socket with correct `0600` permissions, and responds to queries
- [x] No plaintext or hashes ever touch disk
- [x] All Phase 0 invariants documented and upheld in code

## Architecture

### Components

| Component              | Responsibility                              | Key File(s)                  |
|------------------------|---------------------------------------------|------------------------------|
| CLI / Client           | User-facing commands, auto-spawn daemon     | `cmd/blastradius/main.go`    |
| Daemon                 | Singleton background process + IPC server   | `internal/daemon/daemon.go`  |
| Registry               | In-memory Secret Hash storage (hash-only)   | `internal/registry/registry.go` |
| Config                 | Non-sensitive user configuration            | `internal/config/config.go`  |

### Communication

- **Transport:** Unix domain socket (`/tmp/blastradius.sock` by default)
- **Permissions:** `0600` (owner read/write only)
- **Protocol (Phase 0):** Simple line-based commands (`STATUS\n`, `PING\n`, `HALT\n`/`STOP\n`) with JSON responses
- **Singleton enforcement:** Client attempts connection; on failure, spawns daemon binary in background then reconnects

### Data Model

- `SecretHash` = SHA-256 digest (never plaintext)
- Registry is 100% in-memory (`map[SecretHash]Entry`)
- No file paths or sensitive metadata stored in v1 design

## Formal Invariants

These invariants are enforced by the architecture and should be validated in tests:

1. **Hash-only by construction**  
   Plaintext secrets are accepted only as I/O and are hashed immediately via `registry.HashValue()`. The registry never stores or returns plaintext.

2. **No persistence of sensitive state**  
   The `Registry` lives only in memory. On process exit, all hashes are gone. Only `config.yaml` (non-sensitive) may be written to `~/.config/blastradius/`.

3. **Local-only IPC with strict permissions**  
   All communication uses a Unix domain socket created with `0600` permissions. No TCP, no network exposure.

4. **True singleton**  
   Only one daemon instance runs per user. New `blastradius` invocations detect and reuse the existing daemon.

5. **Minimal metadata**  
   Registry entries contain only project associations and timestamps necessary for functionality. File paths are deprioritized.

6. **Safe degradation**  
   If the daemon cannot start or the socket is unavailable, the client reports clearly instead of failing silently or leaking state.

7. **Configuration contains no secrets**  
   `config.yaml` holds only paths, socket location, and preferences.

## Testing & Verification Performed

- `go run ./cmd/blastradius status` successfully starts daemon and reports status
- Second invocation reuses existing daemon (singleton verified)
- Socket created with correct permissions (`srw-------`)
- Registry starts empty and reports `tracked_hashes: 0`
- No disk writes containing secrets or hashes occur

## Known Limitations (Phase 0)

- Protocol is minimal (will be expanded in later phases)
- No file watching or discovery yet (Phase 1)
- Zsh integration not started (Phase 2)
- No pillars implemented yet

## Next Phase

**Phase 1:** Discovery, Registry Population & File Watching

---

*This document serves as the living specification for Phase 0.*