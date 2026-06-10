# AGENTS.md — Blast Radius Contributor & AI Agent Guide

This document captures how to work effectively on Blast Radius. It is the first thing to read when joining or when an agent starts a task.

**Project is alpha software.** No releases, no RCs, no external user base. Interfaces and behavior can still evolve. Present and document the software as it is _today_ only.

## Core Presentation Rule (Non-Negotiable)

**Never reference previous versions of the software, removed features, development phases, "2026 hardenings", "v1 complete + stages remain", legacy shims for compat, or retired plans in user-facing documentation, README, config comments, code comments that users or future agents will read, help text, or status output.**

- Justify _current_ design choices on their current merits (e.g., "The socket path is a hard-coded security invariant... to minimize attack surface"; "fsnotify reactivity is permanently out of scope because attack surface + complexity outweigh benefits. Manual `rescan` + startup discovery is the supported mechanism.").
- When editing docs or comments, ask: "Would this sentence make sense to someone who cloned the repo in 2027 with no knowledge of our history?"
- Historical notes belong only in git history or private plan session notes (never committed to main docs/comments).

Update this rule in AGENTS.md itself if the policy changes.

## The Five Pillars (Idiomatic Framing)

See [docs/pillars/idiomatic_pillars.md](docs/pillars/idiomatic_pillars.md) — this is the authoritative current framing:

- **Pillar 1**: Legitimate Secret Discovery (`.env*` under project_roots + hard-coded bitwarden source via logical collector model; `env_file_patterns` is the P1 authority declaration).
- **Pillar 2**: Illegitimate Secret Residue / "Crumbs" (inversion of P1; high-risk dirs with per-dir `files[]` patterns; **P1 has authority and priority** — enforced by `internal/policy.Classifier`; P1-claimed files are never crumbs).
- **Pillar 3**: History Hygiene (`scrub-history`; delete or redact modes; broad LCD + rotated sibling discovery; v2 regfp receipts for safe incrementality).
- **Pillar 4**: Runtime Environment Hygiene (the `blastradius env [name]` primitive; direct `exec` only — hard invariant; count only, never values; `enabled` for future wiring).
- **Pillar 5**: Clipboard Hygiene (primitives + optional macOS polling monitor with fast first-secret alert + two-tier auto redact-then-clear; config timeouts + placeholder).

Everything else (duplicates, rescan, status, Zsh HUD) supports these pillars. The system is strictly hash-only (SHA-256), minimal-metadata (opaque ProjectIDs), local-only (Unix domain socket), and degrades safely.

## Key Invariants (Current — Hard)

1. Registry **never** contains plaintext secret values.
2. No secret material (plaintext or hashes) is ever written to disk.
3. IPC uses a **hard-coded** local Unix domain socket at `~/.local/state/blastradius/blastradius.sock` (0700 dir + 0600 socket + capability token auth). Path is **not user-configurable**.
4. True singleton background daemon.
5. Minimal metadata only (opaque ProjectIDs).
6. Persisted config (`~/.config/blastradius/config.yaml`) is non-sensitive only.
7. Safe degradation on failure (clear status, never silent bad behavior).
8. Respects ignore patterns + .gitignore + .blastradiusignore.
9. **Pillar 4 / pillar4.commands** are **always** executed via direct `exec` (never `sh -c` or a shell). If you need pipes/complex logic, point at a wrapper script you control.
10. **Pillar 1 has authority over Pillar 2** (Classifier enforces; documented loudly in internal/config/config.example.yaml and code).

Violating any of these is a bug. Tests and reviews must check them.

See `internal/config/config.go` (and normalize.go), `internal/daemon/{daemon,clipboard}.go` (AUTH + token + P5 monitor), `internal/cli/env.go`, `internal/policy/classifier.go`, and `internal/config/config.example.yaml` for the implementations and loud comments.

## Building, Testing, Developing

**Always start here:**

```bash
make help          # self-documenting; shows every target with descriptions
```

Common commands:

- `make test` — full suite (fast, `-timeout=5s`, no coverage).
- `make build` — `go build -o blastradius ./cmd/blastradius`.
- `make cover` — trustworthy **per-package** coverage + uncovered functions (human readable).
- `make test-cover` — **strict CI gate**: per-package + 80% avg + 5s wall-time hard limit (forces `-j4` automatically via Makefile). Must pass.
- `make check` — local safety gate: test + vet + fmt + test-cover.
- `make check-fix` — same but with `fmt-fix` first.
- `make clean` — removes all artifacts (binaries, coverage\*.out, .coverage-failed, test binaries, go caches, etc.). All live in project root.
- `make fmt`, `make fmt-fix`, `make vet`, `make tidy`, `make loc`.

Raw Go still works:

```bash
go run ./cmd/blastradius status
go build -o blastradius ./cmd/blastradius
./blastradius start
./blastradius status --json
```

**Coverage model (important):** A long-standing Go toolchain bug makes `go test -cover ./...` untrustworthy. We collect **one package at a time**. The ugly logic lives only in `scripts/coverage.sh` (black box). When you add/remove/split a package, edit **only** the `PACKAGES := ...` block and the `PKG_foo` lines in [Makefile](Makefile). Everything else derives from it. Per-package numbers in `make cover` are the only ones you should trust.

All artifacts are cleaned by `make clean`. Never leave `.coverage-failed` or stray `*.test` binaries.

## Test Rules (Strict — Especially for Daemon)

- Every test run uses `-timeout=5s` (suite level) or per-package limits.
- **Daemon tests (internal/daemon/\*\_test.go and cross-package that exercise Run/HandleConnection):** NO SLEEPS, no real `time.Ticker`, no background `Run()` loops that can block, no real listeners with timeouts. Use `net.Pipe()` for handleConnection tests. Use the provided test seams/hooks (`pbpasteFunc`/`pbcopyFunc`, `osascriptFunc`, `afplayFunc`, `configLoad` overrides, `GetDaemonLogPathFnForTesting`, etc.). See the comment block in `internal/daemon/daemon_test.go:401` (and surrounding) and the var blocks in `daemon/*.go` (core hooks in daemon.go; P5 clipboard seams in clipboard.go) for the contract. These rules exist so `make test-cover` can stay under the 5s wall-time invariant even under `-j`.
- CLI tests use `silenceOutput()`, `resetTestOverrides()`, `configLoad` / `sendDaemonCommandFn` / `execCommand` overrides (see `internal/cli/testhelpers_test.go` and `cli_test.go`).
- Sources (Bitwarden) use `execBw` hook.
- Hermeticity: never touch real `~/.config/blastradius` or `~/.local/state/blastradius` in tests. Force temp paths via hooks.
- If a test is slow or flaky, it is a bug. Fix the test or the seam, do not increase timeouts.

When adding a new package: add it to Makefile PACKAGES + PKG\_\* map, add a test file, ensure it participates in cover gate.

## Documentation & Config Rules

- Primary user docs: [README.md](README.md), [docs/CURRENT_STATE.md](docs/CURRENT_STATE.md) (current architecture snapshot), [docs/pillars/idiomatic_pillars.md](docs/pillars/idiomatic_pillars.md) (framing), [config.example.yaml](internal/config/config.example.yaml) (loud, example-rich comments are part of the UX).
- `status --json` is the stable machine-readable interface (Zsh and anything else should parse it).
- `blastradius` (no args) and `blastradius help` go through `internal/cli/help.go:PrintHelp` (shows partial live config + commands).
- `blastradius config` must show configuration (see its implementation).
- When you change pillar behavior, config shape, command surface, status fields, defaults, or security invariants:
  - Update the four docs above.
  - Update relevant code comments (godoc + inline).
  - Update `internal/cli/help.go` if command list or examples change.
  - Update tests that assert on output.
  - Run the verification greps (see below).
- Config is the single source of truth for user settings (non-sensitive). Pillar sections are deliberate for clarity.
- `env_file_patterns` under `pillar1.sources.env.options` is the **P1 authority declaration**. Pillar 2 must respect it (Classifier + docs in config.example make this loud).
- After editing config docs, a `blastradius status` (daemon running) or `blastradius config` is the quickest way to see that loading behaved as intended.

## Security Posture (Current)

- Hash-only by construction (never log or store plaintext).
- Local-only Unix socket + token auth.
- Direct exec (no shell) for all configured commands (P4 + any future prompt wiring).
- Minimal metadata.
- Safe degradation + clear errors.
- Designed with a local attacker in mind (hard invariants reduce the surface the attacker can influence).
- Pillar 2 never asks for broad permissions (no Full Disk Access).

If a change would weaken any of the invariants listed earlier, it requires explicit justification and review.

## Common Tasks & Patterns

- **Adding a new source/collector under Pillar 1:** Implement the `sources` interface (Name/Enabled/Collect/Validate), wire it in `discovery/manager.go:NewManager`, add per-source options handling + `GetSourceIgnorePatterns`, update config.example, docs, and status surfaces as needed. Both sources participate in the same registry/rescan/duplicates/status.
- **P2 (Crumbs) cases:** The three supported interactions (separate dirs, P1 disabled, overlapping with P1 claiming only its env_file_patterns) are implemented via Classifier + per-dir files[] model. New P2 configurations or edge cases go through the same surfaces + docs updates.
- **P3 receipts:** The v2 `blastradius-scrub-receipt` lines are the durable signal. `--full` / `--reset` ignores them. See `internal/scrub/policy.go`.
- **P5 monitor:** Polling (750ms hard-coded in alpha for simplicity; logged at start). Two independent timeouts + fast-path first-secret alert. Primitives (`check`/`scrub`/`redact`/`clear`/`nuke`) always work even if monitor disabled. macOS only for the reactive path.
- **Zsh layer:** Intentionally thin (see `zsh/blastradius.zsh`). Prompt segment is fast + safe for every prompt. All heavy work is in the CLI/daemon. Add wrappers for new commands as needed, but keep it formatting + convenience only.
- **Rescan:** Deliberate manual on-demand only (`blastradius rescan` or daemon startup). No fsnotify.

## Workflow for Agents & Humans

1. Read AGENTS.md + Makefile (via `make help`) + the pillar docs relevant to your change.
2. Explore with `grep`, `read_file`, `list_dir`.
3. Make changes with `search_replace` (precise, unique contexts; prefer small targeted replaces).
4. Run `make check` (or at least `make test` + vet + fmt) frequently.
5. For doc-heavy or cross-cutting changes (like this audit), use `todo_write` to track steps visibly.
6. Before declaring done: run the full verification steps in the plan (build, tests, manual CLI, grep sweeps for banned historical language, manual read of changed docs).
7. Update TODO.md only for new actionable items surfaced; do not leave the "documentation audit" item if you just completed it.

## Verification Commands (Run These After Doc/Code Comment Changes)

```bash
# Historical language must be gone from committed sources (test fixtures/dates excepted where they are just "now" values)
grep -r -n --include="*.md" --include="*.yaml" --include="*.go" -E "(Phase [0-9]|2026 harden|post-sunset|recorder pillar|implementation plan|plan session notes|pillar5_user_stories|stages 2-6)" . | grep -v ".git" || echo "CLEAN"

# Legacy compat phrasing (rephrased or removed per policy)
grep -r -n --include="*.md" --include="*.yaml" --include="*.go" -iE "for (full )?backward compat|legacy (default|TargetDirs).*compat|was removed with the redaction" . | grep -v ".git" || echo "CLEAN (or only internal v1/v2 receipt logic)"

make test
make check   # or make -j4 test-cover if you touched coverage-sensitive packages
go run ./cmd/blastradius
go run ./cmd/blastradius config
go run ./cmd/blastradius status --json
```

A clean `git status` + green gates + the above greps + a newcomer can understand the current state from README + `make help` + `blastradius config` means success.

## Other Notes

- Bitwarden collector (internal/sources/bitwarden.go) is functional but the weakest "done" area (folders, orgs, attachments, TOTP, sophisticated bw state handling remain future work — tracked in TODO).
- No editor/AI prompt integration, no true OS clipboard events (polling pragmatic for alpha), no in-memory P3 cache (receipts provide durability; invalidation was judged too hard).
- License: TBD (active development).

When in doubt, make the change that makes the _current_ software clearer and more self-documenting without adding historical baggage.

Update this file when project conventions change (e.g., new hard invariant, new test rule, new doc location).
