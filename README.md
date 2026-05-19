# Blast Radius

**Local, user-space tool to reduce accidental secret exposure and duplication.**

Blast Radius helps developers avoid leaking secrets through common workflow mistakes (e.g., running `printenv` and accidentally pasting output into AI tools, notes, or other contexts). It operates exclusively on cryptographic hashes, maintains minimal in-memory state, and focuses on **visibility + automated cleanup** rather than enforcement.

- Go core daemon (singleton via Unix domain socket)
- Thin Zsh integration layer
- Five extensible pillars for analysis, alerting, redaction, and hygiene

**Current Status:** Phase 0 complete (foundations).

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

## Next Phases (Planned)

See `docs/PHASE0.md` and the full implementation plan for details on upcoming pillars.

## License

To be determined. Currently under active development.

---

**Note:** This project is in early development. Interfaces and behavior will evolve.