# Blast Radius — Current Architecture and Capabilities

**This document provides a snapshot of the current project state.** It is intended for onboarding and as a reference for architecture, decisions, invariants, commands, and known limitations.

The authoritative framing for the system is in [docs/pillars/idiomatic_pillars.md](pillars/idiomatic_pillars.md).

---

## Executive Summary

Blast Radius is a local, hash-only tool for secret exposure reduction and hygiene. Core infrastructure and all five idiomatic pillars are implemented and functional.

**Current pillars (per idiomatic_pillars.md):**

- **Pillar 1**: Legitimate Secret Discovery — ✅ Core complete + `env_file_patterns` authority model.
  - Recursive scanning of `.env*` (or user-declared patterns) under configured `project_roots`.
  - Per-source `ignore_patterns` + global skip/ignore machinery.
  - Logical collector layer: `env` source + hard-coded `bitwarden` source (via official `bw` CLI when enabled).
  - Both sources feed the same in-memory registry, participate in `rescan`, `duplicates`, and `status`.
  - `env_file_patterns` (positive include list under `pillar1.sources.env.options`) is the declaration of P1 authority. Pillar 2 must respect it.
- **Pillar 2**: Illegitimate Secret Residue ("Crumbs") — ✅ Functional.
  - `blastradius crumbs` (and status summary).
  - Only supported config shape is `pillar2.dirs[]` + per-dir `files[]` (per-surface control).
  - `internal/policy.Classifier` enforces that Pillar 1 has authority and priority over Pillar 2. P1-claimed containers are never reported as crumbs.
  - The three supported interactions work: separate directories, P1 source disabled, and overlapping directories (P1 claims only its declared patterns; P2 sees the rest).
- **Pillar 3**: History Hygiene (`scrub-history`) — ✅ Functional.
  - Delete or redact modes, `--dry-run`, `--json`, `--file`, `--full`/`--reset`.
  - Broad discovery: `$HISTFILE`, LCD live files for common shells under `$HOME` (and `history_roots`), plus auto-discovered rotated/backup siblings in the same directories.
  - v2 receipt lines (`# blastradius-scrub-receipt:v2:...:regfp=...`) for durable, deterministic incrementality and external mutation detection. Re-inspects when the registry grows or receipts are stale.
- **Pillar 4**: Runtime Environment Hygiene (the `env` primitive) — ✅ Functional.
  - `blastradius env [name]` (defaults to the `default-env` command = `printenv`).
  - Runs the configured command via direct `exec` (hard invariant — no shell), searches output with the unified detector against the P1 registry, surfaces only a `secrets_found` count (plus logs to daemon), never leaks values.
  - `--json` supported for prompt/machine use. `enabled` field exists for future automation wiring (the primitive itself is the whole of Pillar 4).
- **Pillar 5**: Clipboard Hygiene — ✅ Functional (macOS for reactive parts).
  - Primitives: `status`/`check`, `clear`/`nuke`, `scrub`/`redact`.
  - Optional background monitor (when `monitor_enabled: true`): polling-based reactive alerts on first secret (fast path), plus two-tier auto (redact after `redact_timeout_seconds`, full clear after `full_clear_timeout_seconds`).
  - State surfaced in `status` (and `status --json` under `pillar5`).
  - Placeholders prefer Pillar 5 config, then Pillar 3, then hard default. All primitives work even if the monitor is disabled.

The system remains strictly **hash-only, minimal-metadata, local-only** with safe degradation. Full filesystem reactivity (`fsnotify`) is deliberately and permanently out of scope for security reasons. On-demand manual `rescan` (plus initial discovery at daemon start) is the supported mechanism.

---

## Current Capabilities

| Area                        | Status    | Key Deliverables |
| --------------------------- | --------- | ---------------- |
| Foundations                 | ✅        | Singleton daemon via Unix domain socket (hard-coded path + 0600 + capability token auth), thin CLI coordinator, YAML config (pillar-organized, non-sensitive), safe degradation. |
| Discovery + Registry (P1)   | ✅        | Logical collector model (`env` + `bitwarden`), recursive scan under `project_roots` respecting `env_file_patterns` / ignores / skips, SHA-256 only, opaque ProjectIDs, `duplicates`, on-demand `rescan`, collector results in status. |
| Zsh HUD                     | ✅        | Thin prompt segment (`blastradius_prompt_info`) + convenience wrappers (`blastradius_status`, `blastradius_*` for other commands). Prompt is fast and safe for every invocation. |
| History Hygiene (P3)        | ✅        | `scrub-history` (delete/redact, `--dry-run`/`--json`/`--file`/`--full`), broad LCD + rotated/backup discovery under home + `history_roots`, v2 regfp receipts for incremental + mutation detection, atomic temp+0600+rename writes. |
| Runtime Hygiene (P4)        | ✅        | `blastradius env [name]` primitive: direct exec (hard invariant), unified detection against P1 registry, `secrets_found` count only (never values), logs to daemon, `--json`, `pillar4.commands` + `enabled`. |
| Clipboard Hygiene (P5)      | ✅        | Primitives (`check`/`scrub`/`redact`/`clear`/`nuke`), optional macOS polling monitor (fast first-secret alert + two-tier auto with independent `redact_timeout_seconds` / `full_clear_timeout_seconds`), state in `status`, placeholder preference (P5 > P3 > default). |
| Illegitimate Residue (P2)   | ✅        | `crumbs` command + JSON, `residue` (detector + manager), per-dir `dirs[]` + `files[]` model, daemon handler + status summary, `policy.Classifier` enforcing P1 authority (P1-claimed files never crumbs). |

---

## Current Architecture

### Package Structure

```
cmd/blastradius/
    main.go                 # Ultra-thin entrypoint (testable via run())

internal/
├── cli/                    # ~15 focused files (one per command + cli.go coordinator, conn.go for IPC, clipboard.go/env.go for P4/P5 primitives, test helpers)
│   └── ...
├── daemon/
│   ├── daemon.go           # Core: Unix socket server, capability token auth (hard invariant), handleConnection dispatch, accessors, Run/Close
│   ├── clipboard.go        # Pillar 5 reactive monitor (fast alert + two-tier auto redact/clear) + its test seams (pbpaste etc.)
│   ├── context.go          # DaemonContext type alias (cycle avoidance)
│   └── handlers/           # Thin per-command handlers (most <50 LOC); scrub_history.go is the larger P3 orchestrator
│       └── ...
├── registry/
│   └── registry.go         # In-memory SecretHashRegistry (hash-only by construction)
├── discovery/              # Multi-file (manager + scanner + ignore)
│   ├── ...
├── config/                 # Multi-file
│   ├── config.go           # Pillar structs, DefaultConfig, Load/Save, Get* accessors, hard-coded SocketPath (security invariant)
│   └── normalize.go        # Post-unmarshal normalizers + EffectiveRedactPlaceholder
├── detection/
│   └── detector.go         # Unified candidate extraction (entropy + patterns + assignment + structured) used by P2–P5
├── policy/
│   └── classifier.go       # P1 authority enforcement over P2
├── residue/                # Multi-file (manager + detector + types + safe_names)
│   └── ...
├── sources/                # Multi-file collectors for the logical P1 layer
│   ├── env.go
│   ├── bitwarden.go
│   └── ...
├── scrub/                  # P3 history hygiene (all policy + discovery + processing here)
│   ├── policy.go           # Modes, Entry parse/apply, receipts (v2 regfp), ShouldReprocess, fingerprints
│   └── history.go          # DiscoverHistoryTargets (LCD + rotated), ProcessHistory, LooksLikeRotatedHistory
└── logging/
    └── logging.go          # Daemon + CLI logging (to ~/.local/state/blastradius/)
```

### Key Properties

- Single CLI coordinator (`blastradius` binary handles everything user-facing).
- Daemon is started explicitly via `blastradius start`.
- `status --json` is the stable machine interface.
- Zsh layer is thin formatting only (prompt segment + convenience wrappers).
- All secret detection (P2–P5) routes through the central registry via `CHECK_HASH` + the unified `detection` package.
- P1 authority over P2 is enforced internally by `policy.Classifier` (never surfaced as a conflict to the user; documented in config and code).

---

## Core Invariants (Current)

| #   | Invariant                                                                                                                              | Status |
| --- | -------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| 1   | Registry never contains plaintext                                                                                                      | ✅     |
| 2   | No secret material ever written to disk                                                                                                | ✅     |
| 3   | IPC over Unix domain socket (hard-coded path `~/.local/state/blastradius/blastradius.sock`, 0700 dir + 0600 socket + capability token) | ✅     |
| 4   | True singleton daemon                                                                                                                  | ✅     |
| 5   | Minimal metadata (opaque ProjectIDs)                                                                                                   | ✅     |
| 6   | Persisted config is non-sensitive                                                                                                      | ✅     |
| 7   | Safe degradation on failure                                                                                                            | ✅     |
| 8   | Respects ignore patterns                                                                                                               | ✅     |
| 9   | Pillar 4 / `pillar4.commands` always use direct `exec` only (no shell) — hard security invariant                                       | ✅     |

The socket path and direct-exec rule are hard invariants (not user-configurable) to reduce attack surface. Old top-level discovery keys and `shell:` / `auto_on_prompt` keys under commands are not accepted (and are silently ignored by the YAML unmarshaler if present in user config). The supported shape is the pillar-organized structure in `config.example.yaml`.

---

## Current Commands

```bash
blastradius                  # Help + config location
blastradius start            # Start background daemon + initial discovery
blastradius status [--json]  # Daemon + registry state (tracked hashes, duplicates, scan state, pillar summaries)
blastradius stop / halt      # Graceful shutdown
blastradius logs             # View daemon log
blastradius duplicates       # Pillar 1: cross-project secret duplication
blastradius crumbs           # Pillar 2: forgotten vault exports & high-entropy dumps in high-risk dirs
blastradius scrub-history    # Pillar 3: scrub known secrets from shell history (--mode, --dry-run, --json, --file, --full)
blastradius rescan           # Pillar 1: trigger manual on-demand rescan
blastradius env [--json] [name]  # Pillar 4 primitive: run cmd (direct exec), search output for secrets, report count (no values)
blastradius clipboard        # Pillar 5: status|check|clear|nuke|scrub|redact (primitives + monitor-backed alerts + two-tier auto)
blastradius config           # Show configuration
```

Zsh integration (source `zsh/blastradius.zsh`):

- `blastradius_prompt_info` — compact prompt segment (Pillar 1 count)
- `blastradius_status` + thin wrappers for other commands

---

## Known Limitations / Future Work

- **Pillar 1 reactivity**: Full filesystem reactivity (`fsnotify` / automatic rescan on file changes) is **deliberately not implemented** and is permanently out of scope. The security surface area and complexity outweigh the benefits. On-demand manual `rescan` (plus initial discovery at daemon start) is the supported and intentional mechanism.
- No editor / AI prompt integration.
- Pillar 5 monitor is polling-based (pragmatic 750ms interval, hard-coded for alpha; true OS-level change events are future work).
- **Pillar 3** post-v1 items (fish structured redaction for its YAML-ish format, fake secrets replacement mode research spike, surface pillar3 observability in `status --json`) are tracked in [TODO.md](../TODO.md).
- Bitwarden collector (P1 source) is functional for common cases (logins, notes, custom fields) but does not yet handle folders, organizations, attachments, TOTP, or sophisticated error handling around `bw` states well. This is the least complete area of the P1 surface.
- One optional powerful P2 story (lightweight git accident detection: reflog + stash + uncommitted tree + bounded recent commits) remains in TODO.

All secret detection across Pillars 2–5 routes through the single `internal/detection` package (robust candidate extraction with wrappers, context-aware assignment parsing, high-entropy regex seeds, structured data walking, and entropy gating). This is the current implementation.

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
