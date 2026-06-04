# Blast Radius

**Local, user-space tool to reduce accidental secret exposure and duplication.**

Blast Radius helps developers avoid leaking secrets through common workflow mistakes (e.g., running `printenv` and accidentally pasting output into AI tools, notes, or other contexts). It operates exclusively on cryptographic hashes, maintains minimal in-memory state, and focuses on **visibility + automated cleanup** rather than enforcement.

- Go core daemon (singleton via Unix domain socket)
- Thin Zsh integration layer
- Five extensible pillars for analysis, alerting, and hygiene

**Current Status:** Core daemon, discovery (Pillar 1), residue hunting (Pillar 2), and hygiene pillars (3–5) are implemented. See [docs/pillars/idiomatic_pillars.md](docs/pillars/idiomatic_pillars.md) for the current framing and [docs/CURRENT_STATE.md](docs/CURRENT_STATE.md) for architecture, commands, invariants, and capabilities.

## Building & Running

```bash
go build -o blastradius ./cmd/blastradius
./blastradius status
```

Or run directly:

```bash
go run ./cmd/blastradius status
```

## Developing Locally

The project provides a friendly, self-documenting Makefile.

```bash
make help          # start here — shows every command with descriptions
make test
make build
make cover         # trustworthy per-package coverage numbers (the ones you can believe)
make test-cover    # the strict CI gate (parallelism is forced automatically; must finish <5 s)
make clean
```

All artifacts (coverage files, test binaries, `.coverage-failed`, etc.) live in the project root and are removed by `make clean`.

See the "Coverage model" section near the top of [Makefile](Makefile) for the (now short) explanation of the per-package coverage approach. A long-standing Go toolchain bug makes combined `go test -cover ./...` numbers untrustworthy; the Makefile is deliberately self-documenting and approachable for newcomers.

## Architecture (High Level)

- `cmd/blastradius` — CLI entrypoint (client + daemon mode)
- `internal/daemon` — Unix socket server + request handling
- `internal/registry` — In-memory hash registry (hash-only by construction)
- `internal/config` — YAML configuration (non-sensitive)

## Security Posture

- Hash-only operation (never stores or logs plaintext)
- Minimal metadata (opaque ProjectIDs in the registry)
- Local-only communication over Unix domain socket
- **Hard security invariants**:
  - The IPC socket path is **not user-configurable** and always lives at `~/.local/state/blastradius/blastradius.sock` (0700 dir + 0600 socket + capability token auth).
  - Pillar 4 (`env`) primitive commands (and any commands under `pillar4.commands`) are **always executed via direct `exec` with no shell** (`sh -c` is never used). For complex logic, point at a wrapper script you control.
- Additional runtime hardening (current):
  - Bare names for internal tools (`bw`, pbpaste/pbcopy/osascript/afplay) and user P4 bare commands are resolved via LookPath (best-effort absolute) to reduce PATH hijacking surface. Explicit relative paths for P4 are executed as written (caller cwd).
  - P1 directory walks and P2 walks + file scans explicitly skip symlinks (never follow). Narrow TOCTOU between Lstat decisions and later reads is documented; declared surfaces + Classifier (P1 authority) are primary containment.
- Safe degradation on failure
- Designed with a local attacker in mind

## Zsh Integration

Blast Radius provides a thin, composable Zsh layer.

### Quick Start

```bash
# Source the plugin (add to your ~/.zshrc)
source /path/to/blast-radius/zsh/blastradius.zsh

# Add a compact status indicator to your prompt
PROMPT='$(blastradius_prompt_info) '$PROMPT
```

### Available Functions

| Function                    | Description                                      |
|----------------------------|--------------------------------------------------|
| `blastradius_prompt_info`  | Returns a compact colored segment for your prompt (e.g. `[BR:142]`) |
| `blastradius_status`       | Shows full human-readable daemon status          |

### Prompt Segment Example Output

- `[BR:142|completed]` — Daemon healthy, 142 secrets tracked, scan finished
- `[BR:off]` — Daemon not running

The segment is designed to be **fast** and safe to call on every prompt.

### Hook Support

The Zsh layer provides a thin prompt segment for daemon visibility. Additional hooks can be added by users for custom workflows.

## License

To be determined. Currently under active development.

---

**Note:** This project is in early development. Interfaces and behavior will evolve.

See `docs/pillars/idiomatic_pillars.md` for the current five-pillar framing and `docs/CURRENT_STATE.md` for the detailed architecture snapshot.

