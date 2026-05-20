# Blast Radius — Current State & Architecture (as of 2026-05-20)

**This document provides a complete snapshot of the project state.**  
It is intended to serve as the primary context document when restarting conversations or onboarding.

---

## Executive Summary

Blast Radius has completed **Phases 0, 1, 2, and 3**.

- **Phase 0**: Foundations, singleton daemon, Unix domain socket IPC, CLI structure, invariants.
- **Phase 1**: Discovery engine, `.env*` scanning, SHA-256 hashing, ignore patterns, aggressive pruning, scan state tracking, proper file logging.
- **Phase 2**: Zsh integration layer + composable prompt HUD.
- **Phase 3**: Pillar 1 (Duplicate Alerting) + Pillar 4 (History Hygiene) + major refactoring + security cleanup.

**Current focus**: Preparing for **Phase 4** (Pillar 3 – CLI Output Redaction), which is the most technically complex phase.

The project follows a strict **hash-only, minimal-metadata, local-only** philosophy with strong emphasis on safe degradation and attack surface elimination.

---

## Completed Phases

| Phase | Name                              | Status     | Key Deliverables |
|-------|-----------------------------------|------------|------------------|
| 0     | Foundations & Core Architecture   | ✅ Complete | Singleton daemon, Unix socket, CLI skeleton, invariants, config system |
| 1     | Discovery, Registry & File Watching | ✅ Complete | Recursive `.env*` discovery, SHA-256, ignore engine, pruning, scan state, logging to file |
| 2     | Zsh Integration & Ambient HUD     | ✅ Complete | Composable prompt functions, `--json` status, plugin |
| 3     | Pillar 1 + Pillar 4               | ✅ Complete | Duplicate detection, `duplicates` command, history scrubbing, major refactor |

---

## Current Architecture (Post-Refactor)

### Package Structure

```
cmd/blastradius/
    main.go                 # Thin dispatcher only

internal/
├── cli/
│   └── cli.go              # All command implementations (RunStatus, RunStart, RunDuplicates, etc.)
├── daemon/
│   └── daemon.go           # Unix socket server + request routing + graceful shutdown
├── registry/
│   └── registry.go         # In-memory SecretHashRegistry (core data structure)
├── discovery/
│   ├── manager.go          # Discovery orchestration + project metadata
│   ├── scanner.go          # Recursive walk + hashing + pruning
│   └── ignore.go           # gitignore-style pattern matching
├── config/
│   └── config.go           # YAML loading + defaults
└── (no logger package yet — using std log routed to file)
```

### Key Design Decisions Made

1. **Opaque ProjectID (Critical)**
   - `ProjectID` is **not** a filesystem path.
   - It is the first 8 characters of the SHA-256 hash of the canonical directory path.
   - The `Registry` only ever sees opaque IDs.
   - `DiscoveryManager` maintains the mapping to human-friendly display names (`.../project/backend`).
   - Full paths exist only transiently during discovery and are discarded.
   - This significantly reduces the sensitivity of in-memory state.

2. **Logging Strategy**
   - Daemon and discovery code **always** log via Go's `log` package.
   - Output goes to: `~/.local/state/blastradius/daemon.log`
   - Client commands use `fmt` for terminal output (correct separation).
   - No more terminal pollution from the daemon.

3. **Scan State**
   - Exposed via `status`: `not_started` | `in_progress` | `completed` | `failed`
   - Users can start the daemon and check progress asynchronously.

4. **CLI Structure**
   - `blastradius` (no args) and `blastradius help` → show help + config location (never starts daemon)
   - `blastradius start` → explicitly start daemon
   - `blastradius status` → does **not** auto-start
   - `blastradius stop` / `halt` → graceful shutdown
   - `blastradius duplicates` → Pillar 1
   - `blastradius scrub-history` → Pillar 4
   - `blastradius logs` → view daemon log

5. **Performance / Pruning**
   - Hardcoded aggressive skip list for common heavy directories (`node_modules`, `.git`, `vendor`, etc.).
   - Also respects `.gitignore` + `.blastradiusignore`.
   - Configurable via `skip_dirs` and `ignore_files` in config (with safe defaults).

---

## Core Invariants (Current Status)

All original invariants remain upheld:

| # | Invariant | Status | Notes |
|---|-----------|--------|-------|
| 1 | Registry never contains plaintext | ✅ | Hashing happens at discovery edge |
| 2 | No secret material ever written to disk | ✅ | Registry is purely in-memory |
| 3 | IPC over Unix domain socket with `0600` | ✅ | Enforced on bind |
| 4 | True singleton | ✅ | Connection-first detection |
| 5 | **Minimal metadata** | ✅ **Strengthened** | Opaque `ProjectID` + display names only |
| 6 | Persisted state is non-sensitive | ✅ | Config only |
| 7 | Safe degradation | ✅ | Clear status reporting |
| 8 | Respects ignore patterns | ✅ | Active in scanner |

---

## Data Model (Registry)

- `SecretHash` = `[32]byte` (SHA-256 of secret **value** only)
- `ProjectID` = opaque string (first 8 hex chars of path hash)
- `Entry` contains only: `map[ProjectID]struct{}` + `LastSeen`
- No file paths, no keys, no plaintext — ever.

Display names are resolved on-demand via `DiscoveryManager.GetProjectDisplayName()` for user-facing output.

---

## Current Commands (Working)

```bash
blastradius                  # Help + config location (safe)
blastradius start            # Start daemon (scans in background)
blastradius status           # Full status + scan_state + duplicates count
blastradius status --json    # Machine readable
blastradius stop             # Graceful shutdown
blastradius duplicates       # Show cross-project secret duplication
blastradius scrub-history    # Remove known secrets from Zsh history (atomic)
blastradius logs             # View daemon log file
```

---

## Known Limitations / Future Work

- Full reactive file watching (`fsnotify`) is **not yet implemented** (initial discovery only).
- Pillar 2 (Clipboard) — not started.
- Pillar 3 (CLI Output Redaction) — **next major phase** (technically complex).
- Pillar 5 (Runtime Hygiene) — not started.
- Zsh `preexec` / `precmd` hooks exist as skeletons only.
- No editor/AI integration (out of v1 scope).
- History scrubbing currently only supports Zsh.

---

## Recommended Next Steps (Phase 4 Focus)

Phase 4 (Pillar 3) will require careful design around:

- Detecting sensitive commands in `preexec`
- Safe manipulation of Zsh history (`fc`)
- Terminal output redaction strategy (history rewrite + prompt reset vs more advanced techniques)
- Balancing correctness with terminal compatibility

A detailed design discussion is recommended before implementation.

---

## How to Build & Run

```bash
go build -o blastradius ./cmd/blastradius

./blastradius start
./blastradius status
./blastradius logs
```

Config location: `~/.config/blastradius/config.yaml`  
Example config: `config.example.yaml`

---

## Philosophy & Principles (Still Active)

- YAGNI + KISS + Earn Your Abstractions
- Eliminate attack surface rather than reduce it
- Hash-only by construction
- Minimal metadata (especially paths)
- Safe degradation
- Composability (Zsh layer)
- Logging always goes to the logger for daemon paths

---

*This document should be updated after every major phase or significant architectural decision.*
