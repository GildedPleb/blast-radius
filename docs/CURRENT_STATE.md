# Blast Radius — Current State (Post Redaction/Recorder Pillar Sunset)

**Date:** 2026 (post-sunset)

**This document provides a snapshot of the current project state.** It is intended to serve as onboarding and context for the state after the full removal of the terminal redaction / explicit protection / recorder pillar.

The authoritative framing for the system is now in [docs/pillars/idiomatic_pillars.md](pillars/idiomatic_pillars.md).

---

## Executive Summary

Blast Radius is a local, hash-only tool for secret exposure reduction. It has completed core infrastructure and four of the five idiomatic pillars. The complex "Pillar 3 / Phase 4" terminal redaction and per-TTY PTY recorder system (protection mode, `blastradius redact`, sealed windows, `REPLAY_REDACTED` protocol, etc.) has been **fully removed** as it proved disproportionately difficult to maintain and reason about.

**Current pillars (per idiomatic_pillars.md):**

- **Pillar 1**: Legitimate Secret Discovery (`.env*` scanning + registry) — ✅ Implemented
- **Pillar 2**: Illegitimate Secret Residue ("Crumbs") — ✅ **v1 implemented** (`blastradius crumbs`). Scans user-configured high-risk dirs (Downloads/Documents/Desktop + opt-in) for vault exports + high-entropy residue using fixed detectors + registry cross-check. On-demand only. Full stages 2-6 remain for complete pillar (see pillar2-implementation-plan.md).
- **Pillar 3**: History Hygiene (`scrub-history`) — ✅ Implemented
- **Pillar 4**: Runtime Environment Hygiene (`env` / user-defined commands) — ✅ Implemented
- **Pillar 5**: Clipboard Hygiene (`clipboard`) — ✅ Implemented (auto-clear timer not yet built)

The system remains strictly **hash-only, minimal-metadata, local-only** with safe degradation.

---

## Completed Work

| Area                                     | Status             | Key Deliverables                                                                                                                                                                    |
| ---------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Foundations (Phase 0)                    | ✅ Complete        | Singleton daemon, Unix socket (0600), CLI coordinator, config system, invariants                                                                                                    |
| Discovery + Registry (Pillar 1)          | ✅ Complete        | Recursive `.env*` scanning, SHA-256 hashing, ignore engine, pruning, opaque ProjectIDs, duplicates detection                                                                        |
| Zsh HUD                                  | ✅ Complete        | Thin prompt segment + status wrappers (no capture hooks)                                                                                                                            |
| History Hygiene (Pillar 3)               | ✅ Complete        | `scrub-history` command + daemon handler                                                                                                                                            |
| Runtime Hygiene (Pillar 4)               | ✅ Complete        | `env` command, extensible `pillar5_commands` in config                                                                                                                              |
| Clipboard Hygiene (Pillar 5)             | ✅ Complete        | `clipboard` status/check/clear (macOS)                                                                                                                                              |
| Redaction/Recorder Pillar                | ❌ **Removed**     | Entire `recorder/` package, protection mode, `redact [N]`, per-TTY sockets, sealed windows, and all supporting code/docs deleted                                                    |
| Pillar 2 (Illegitimate Residue / Crumbs) | ✅ **v1 complete** | `crumbs` command + `residue` package (detector + manager) + daemon handler + status integration. Config section `residue_hunter`. See implementation plan for remaining stages 2-6. |

---

## Current Architecture

### Package Structure

```
cmd/blastradius/
    main.go                 # Ultra-thin entrypoint

internal/
├── cli/
│   └── cli.go              # Coordinator for all commands (start, status, stop, duplicates, scrub-history, env, clipboard, config, help)
├── daemon/
│   └── daemon.go           # Unix socket server + handlers (STATUS, DUPLICATES, SCRUB_HISTORY, CHECK_HASH, etc.)
├── registry/
│   └── registry.go         # In-memory SecretHashRegistry (hash-only)
├── discovery/
│   ├── manager.go
│   ├── scanner.go
│   └── ignore.go
├── config/
│   └── config.go           # YAML + defaults (no RedactionConfig)
└── logging/
    └── logging.go          # Daemon-only logging (recorder helpers removed)
```

No `recorder/` package remains.

### Key Properties

- Single CLI coordinator (`blastradius` binary handles everything user-facing).
- Daemon is started explicitly via `blastradius start`.
- `status --json` is the stable machine interface.
- Zsh layer is thin formatting only (prompt segment + convenience wrappers).
- All secret detection uses the central registry via `CHECK_HASH`.

---

## Core Invariants (Current)

| #   | Invariant                               | Status |
| --- | --------------------------------------- | ------ |
| 1   | Registry never contains plaintext       | ✅     |
| 2   | No secret material ever written to disk | ✅     |
| 3   | IPC over Unix domain socket with 0600   | ✅     |
|     | **Hard invariant since 2026**: path is not user-configurable; always `~/.local/state/blastradius/blastradius.sock` + 0700 dir + 0600 socket + capability token | |
| 4   | True singleton daemon                   | ✅     |
| 5   | Minimal metadata (opaque ProjectIDs)    | ✅     |
| 6   | Persisted config is non-sensitive       | ✅     |
| 7   | Safe degradation on failure             | ✅     |
| 8   | Respects ignore patterns                | ✅     |
| 9   | **Pillar 5 commands use direct exec only (no shell)** | ✅ (2026) |

**Note on removed configuration options (2026 hardenings):**
- `socket_path` is no longer accepted in `config.yaml` (the path is now a hard-coded invariant).
- The `shell:` key under `pillar5_commands` is no longer accepted. All commands run via direct `exec`.
Old keys are silently ignored by the YAML parser. Users relying on previous behavior should migrate to wrapper scripts for complex commands and remove the old keys.

---

## Current Commands

```bash
blastradius                  # Help + config location
blastradius start            # Start background daemon + initial discovery
blastradius status [--json]  # Daemon + registry state (tracked hashes, duplicates, scan state)
blastradius stop / halt      # Graceful shutdown
blastradius duplicates       # Pillar 1: cross-project secret duplication
blastradius crumbs           # Pillar 2: forgotten vault exports & high-entropy residue in high-risk dirs
blastradius scrub-history    # Pillar 3: scrub known secrets from shell history
blastradius env [name]       # Pillar 4: run runtime hygiene command (e.g. printenv)
blastradius clipboard        # Pillar 5: clipboard status / clear (macOS)
blastradius logs             # View daemon log
blastradius config           # Basic config surface
```

Zsh integration (source `zsh/blastradius.zsh`):

- `blastradius_prompt_info` — compact prompt segment
- `blastradius_status`

---

## Known Limitations / Future Work

- **Pillar 2 (Crumbs)**: v1 shipped (on-demand `crumbs`, fixed detectors for exports + entropy, status summary, opt-in config). Remaining required stages (hunt_residue patterns inside target_dirs, materialization roots expansion, git accident detection, background scheduling, Zsh HUD) are documented in `docs/pillars/pillar2-implementation-plan.md` and `residue_hunter_scoped.md`.
- No reactive file watching (`fsnotify`) — discovery runs on daemon start only.
- History scrubbing supports Zsh only.
- No editor / AI prompt integration.
- Clipboard auto-clear timer (Pillar 5) is declared in config but not yet implemented.

---

## How to Build & Run

```bash
go build -o blastradius ./cmd/blastradius
./blastradius start
./blastradius status
```

Config: `~/.config/blastradius/config.yaml` (see `config.example.yaml`)

---

## Philosophy (Unchanged)

- YAGNI + KISS + Earn Your Abstractions
- Eliminate attack surface
- Hash-only by construction
- Minimal metadata
- Safe degradation
- Thin composable layers (Zsh)

---

_Update this document whenever the pillar surface or core architecture changes._
