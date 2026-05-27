# Blast Radius

**Local, user-space tool to reduce accidental secret exposure and duplication.**

Blast Radius helps developers avoid leaking secrets through common workflow mistakes (e.g., running `printenv` and accidentally pasting output into AI tools, notes, or other contexts). It operates exclusively on cryptographic hashes, maintains minimal in-memory state, and focuses on **visibility + automated cleanup** rather than enforcement.

- Go core daemon (singleton via Unix domain socket)
- Thin Zsh integration layer
- Five extensible pillars for analysis, alerting, redaction, and hygiene

**Current Status:** All phases complete. Single CLI coordinator, TTY discovery, thin Zsh broker. See docs/CLI_REFACTOR_DESIGN.md.

See [docs/CURRENT_STATE.md](docs/CURRENT_STATE.md) for a detailed snapshot of architecture, decisions, invariants, and current capabilities.

## Phase 0 – Foundations (Completed)

- Singleton background daemon using Unix domain sockets with strict `0600` permissions
- Clean `blastradius status` command (auto-starts daemon if needed)
- In-memory `SecretHashRegistry` (SHA-256 only, never stores plaintext)
- Configuration loading from `~/.config/blastradius/config.yaml` (non-sensitive only)
- All Phase 0 invariants upheld and documented
- No secrets or hashes ever written to disk

### Key Invariants (Phase 0)

1. The registry **never** contains plaintext secret values.
2. No secret material (plaintext or hashes) is ever written to disk.
3. All IPC uses a local Unix domain socket with `0600` permissions.
4. The background process is a true singleton.
5. Only non-sensitive configuration is persisted.
6. Failures degrade safely with clear status reporting.
7. **Plaintext secret lifetime in the recorder is explicitly bounded** by `redaction.buffer` (default 1). Windows are sealed (raw bytes discarded) as they age out; `status --json` surfaces the current raw window count for audit. `redact [N]` fidelity is capped by the same bound.

## Building & Running

```bash
go build -o blastradius ./cmd/blastradius
./blastradius status
```

Or run directly:

```bash
go run ./cmd/blastradius status
```

## Architecture (High Level)

- `cmd/blastradius` — CLI entrypoint (client + daemon mode)
- `internal/daemon` — Unix socket server + request handling
- `internal/registry` — In-memory hash registry (hash-only by construction)
- `internal/config` — YAML configuration (non-sensitive)

## Security Posture

- Hash-only operation
- Minimal metadata
- Local-only communication
- Safe degradation on failure
- Designed with a local attacker in mind

## Zsh Integration (Phase 2)

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
| `blastradius_prompt_info`  | Returns a compact colored segment for your prompt (e.g. `[BR:142|completed]`) |
| `blastradius_status`       | Shows full human-readable daemon status          |
| `blastradius_is_running`   | Returns 0 if daemon is running                   |

### Prompt Segment Example Output

- `[BR:142|completed]` — Daemon healthy, 142 secrets tracked, scan finished
- `[BR:off]` — Daemon not running

The segment is designed to be **fast** and safe to call on every prompt.

### Future Hook Support

Skeletons for `preexec` and `precmd` are provided for upcoming features (command redaction, history hygiene).

## Next Phases (Planned)

See the implementation plan for details on Pillars 1–5.

## License

To be determined. Currently under active development.

---

**Note:** This project is in early development. Interfaces and behavior will evolve.

## Migration (post phase 5)
- Single entrypoint: `blastradius`
- Protection: `blastradius protection start|stop`
- Zsh: source new thin blastradius.zsh (no BR_* vars)
- Old recorder direct removed (clean break)

