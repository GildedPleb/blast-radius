# Blast Radius — Current State (Post Redaction/Recorder Pillar Sunset)

**Date:** 2026 (post-sunset)

**This document provides a snapshot of the current project state.** It is intended to serve as onboarding and context for the state after the full removal of the terminal redaction / explicit protection / recorder pillar.

The authoritative framing for the system is now in [docs/pillars/idiomatic_pillars.md](pillars/idiomatic_pillars.md).

---

## Executive Summary

Blast Radius is a local, hash-only tool for secret exposure reduction. It has completed core infrastructure and four of the five idiomatic pillars. The complex "Pillar 3 / Phase 4" terminal redaction and per-TTY PTY recorder system (protection mode, `blastradius redact`, sealed windows, `REPLAY_REDACTED` protocol, etc.) has been **fully removed** as it proved disproportionately difficult to maintain and reason about.

**Current pillars (per idiomatic_pillars.md):**

- **Pillar 1**: Legitimate Secret Discovery — ✅ Core complete + env_file_patterns authority model
  - Key filtering for non-secrets (Phase 1)
  - Improved ignore engine (Phase 2)
  - High-quality manual `rescan` (Phase 3 — deliberate design choice; fsnotify reactivity permanently out of scope for security reasons)
  - Logical layer with explicit sources: `env` + hard-coded `bitwarden` (Phase 4)
  - Both sources participate in rescan, duplicates, and status via the collector model
  - `env_file_patterns` (positive include list) added under pillar1.sources.env.options — this is the declaration of P1 authority that Pillar 2 must respect.
  - Full documentation and example config updated (P1 precedence rule documented loudly)
- **Pillar 2**: Illegitimate Secret Residue ("Crumbs") — ✅ **v1 + Coordination Foundation (Stage 1.5)**
  `blastradius crumbs`. Only supported config shape is `pillar2.dirs[]` + per-dir `files[]` (per-surface control).
  Internal `policy.Classifier` enforces "Pillar 1 has authority and priority over Pillar 2".
  The three user stories work correctly; P1-claimed containers are never reported as crumbs.
  CLI command + status integration shipped in Stage 1; 1.5 added the authority foundation. Full stages 2-6 remain.
  See the 2026 P2 audit notes in the Known Limitations section below, config.example.yaml (loud P1 precedence docs), and [TODO.md](../TODO.md) for the remaining Stages 2–6 (now tracked as individual stories after the detailed plan was retired).
- **Pillar 3**: History Hygiene (`scrub-history`) — ✅ v1 + major blast-radius gap closed (broad auto-rotated + history_roots discovery, v2 regfp receipts for sustainable incrementality + deterministic rewrite/restore observation, `--full`, multi-artifact runs, full tests). Remaining post-v1 items (fish structured redaction, fake secrets, pillar3 observability in status) tracked in [TODO.md](../TODO.md).
- **Pillar 4**: Runtime Environment Hygiene (the `env` primitive function call) — ✅ Implemented
- **Pillar 5**: Clipboard Hygiene (`clipboard`) — ✅ Implemented (auto-clear timer not yet built)

The system remains strictly **hash-only, minimal-metadata, local-only** with safe degradation.

---

## Completed Work

| Area                                     | Status             | Key Deliverables                                                                                                                                                             |
| ---------------------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Foundations (Phase 0)                    | ✅ Complete        | Singleton daemon, Unix socket (0600), CLI coordinator, config system, invariants                                                                                             |
| Discovery + Registry (Pillar 1)          | ✅ Complete        | Recursive `.env*` scanning, SHA-256 hashing, ignore engine, pruning, opaque ProjectIDs, duplicates detection                                                                 |
| Zsh HUD                                  | ✅ Complete        | Thin prompt segment + status wrappers (no capture hooks)                                                                                                                     |
| History Hygiene (Pillar 3)               | ✅ v1 + gap closed | `scrub-history` + broad discovery (rotated siblings + `history_roots`), v2 regfp receipts for incremental + deterministic rewrite/restore detection, `--full`. See TODO for remaining post-v1 items. |
| Runtime Hygiene (Pillar 4)               | ✅ Complete        | `env` primitive function call (runs cmds, searches output, surfaces count only, logs to daemon); `pillar4.commands` + `enabled` |
| Clipboard Hygiene (Pillar 5)             | ✅ Complete        | `clipboard` status/check/clear (macOS)                                                                                                                                       |
| Redaction/Recorder Pillar                | ❌ **Removed**     | Entire `recorder/` package, protection mode, `redact [N]`, per-TTY sockets, sealed windows, and all supporting code/docs deleted                                             |
| Pillar 2 (Illegitimate Residue / Crumbs) | ✅ **v1 complete** | `crumbs` command + `residue` package (detector + manager) + daemon handler + status integration. Config section `pillar2`. See implementation plan for remaining stages 2-6. |

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

| #   | Invariant                                                                                                                                                      | Status    |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| 1   | Registry never contains plaintext                                                                                                                              | ✅        |
| 2   | No secret material ever written to disk                                                                                                                        | ✅        |
| 3   | IPC over Unix domain socket with 0600                                                                                                                          | ✅        |
|     | **Hard invariant since 2026**: path is not user-configurable; always `~/.local/state/blastradius/blastradius.sock` + 0700 dir + 0600 socket + capability token |           |
| 4   | True singleton daemon                                                                                                                                          | ✅        |
| 5   | Minimal metadata (opaque ProjectIDs)                                                                                                                           | ✅        |
| 6   | Persisted config is non-sensitive                                                                                                                              | ✅        |
| 7   | Safe degradation on failure                                                                                                                                    | ✅        |
| 8   | Respects ignore patterns                                                                                                                                       | ✅        |
| 9   | **Pillar 5 commands use direct exec only (no shell)**                                                                                                          | ✅ (2026) |

**Note on removed configuration options (2026 hardenings):**

- `socket_path` is no longer accepted in `config.yaml` (the path is now a hard-coded invariant).
- The `shell:` key under the old `pillar5_commands` (now `pillar4.commands`) is no longer accepted. All commands run via direct `exec` (hard invariant of the Pillar 4 primitive).
  Old keys are silently ignored by the YAML parser. Users relying on previous behavior should migrate to wrapper scripts for complex commands and remove the old keys.
- The `auto_on_prompt` key under `pillar4.commands[].*` was renamed to `enabled` (to reflect that the primitive is the core and auto/prompt wiring is future work). Old keys are ignored; `enabled` defaults to false.

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
blastradius env [--json] [name]  # Pillar 4 primitive: run cmd, search output for secrets, report count (no values); --json for prompts
blastradius clipboard        # Pillar 5: clipboard status / clear (macOS)
blastradius logs             # View daemon log
blastradius config           # Basic config surface
```

Zsh integration (source `zsh/blastradius.zsh`):

- `blastradius_prompt_info` — compact prompt segment
- `blastradius_status`

---

## Known Limitations / Future Work

- **Pillar 1**: Key filtering for non-secret .env keys (via `pillar1.sources.env.options.ignore_patterns` under the logical layer) and collector-based rescan for sources (env + bitwarden) are complete.
- **Pillar 1 reactivity**: Full filesystem reactivity (`fsnotify` / automatic rescan on file changes) is **deliberately not implemented** and is permanently out of scope. The security surface area and complexity were judged to outweigh the benefits. On-demand manual `rescan` (plus initial discovery at daemon start) is the supported and intentional mechanism.
- No editor / AI prompt integration.
- Clipboard auto-clear timer (Pillar 5) is declared in config but not yet implemented.
- **Pillar 3** v1 is complete (modes + dry-run + multi-shell). Deferred post-v1 items (fake secrets spike, fish structured redaction, pillar3 observability in status) are tracked in [TODO.md](../TODO.md).

**Architecture improvement (2026)**: All secret detection across Pillars 2–5 now routes through a single `internal/detection` package with robust candidate extraction (wrappers, context, whitespace fallback, entropy + patterns). This replaced previous naive whole-line/blob or hash-hex-grep approaches. See plan session notes for details.

---

## How to Build & Run

```bash
make help          # recommended starting point — lists every developer command
make test
make build
make cover         # trustworthy per-package coverage (the only numbers you should trust)
make test-cover    # the full strict gate used by CI (parallelism forced automatically; <5 s invariant)
```

All build, test, and coverage artifacts live in the project root and are cleaned with `make clean`.

See the "Coverage model" section near the top of [Makefile](../Makefile) (the short block after the parallelism hack) for why coverage collection is deliberately per-package. A long-standing Go toolchain bug makes combined `go test -cover ./...` numbers untrustworthy here; the Makefile is now self-documenting around that constraint.

Raw Go commands still work:

```bash
go build -o blastradius ./cmd/blastradius
./blastradius start
./blastradius status
```

Config: `~/.config/blastradius/config.yaml` (see `config.example.yaml`)

---

## Philosophy

- YAGNI + KISS + Earn Your Abstractions
- Code is for humans
- Eliminate attack surface
- Hash-only by construction
- Minimal metadata
- Safe degradation
- Thin composable layers (Zsh)

---

_Update this document whenever the pillar surface or core architecture changes._
