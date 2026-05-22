# Blast Radius — Phase 4 Design Document

**Pillar 3: CLI Output Redaction**
**Version 1.0** | **2026-05-22** | **Status: Implementation Complete (v1)**

---

## 1. Executive Summary & Goals

**Phase 4** implements **Pillar 3 (CLI Output Redaction)** — the most technically complex pillar in the original specification.

### Primary Goal

Enable the system to **alter previously displayed terminal content** after the user has finished interacting with it, so that accidental long-term exposure (e.g., copying terminal scrollback into AI prompts days later) is dramatically reduced.

### Core User Story (Locked)

1. User runs a command that prints secrets (e.g., `printenv`).
2. User sees the **full, unaltered output** (non-interference requirement).
3. User runs any subsequent command (thus signaling they are done with the previous output).
4. On the next prompt cycle the system:
   - Detects that sensitive output was produced.
     After a configurable buffer of prompt cycles the system:
   - Fully clears the terminal.
   - Rebuilds a clean, redacted version of the session history from its own captured data.
   - Shows a new prompt.
5. The terminal is now in a provably safer state for future copy/paste operations.

### Success Criteria for v1

- Catch ~95% of real secrets that appear in common developer workflows.
- Never interfere with the user's original command output while they are actively viewing it.
- Provide a powerful, composable `blastradius clear` function that can be triggered automatically or manually.
- Maintain the project's core invariants (hash-only, minimal metadata, local-only, safe degradation).

---

## 2. Non-Goals (Explicitly Out of Scope for v1)

- Perfect detection of every possible secret format (especially complex multi-line secrets).
- Surgical redaction of already-scrolled content in the terminal's internal scrollback buffer.
- Cross-terminal secret correlation or alerting (e.g., "this secret appeared in 3 terminals").
- Deep integration with specific terminal emulators (iTerm2 proprietary features, VS Code extensions, etc.).
- Automatic redaction _before_ output is displayed to the user.
- Support for Windows terminals or non-Zsh shells.
- Encrypted persistence of session history.
- Real-time collaborative features or shared sessions.

**We explicitly accept** that some edge-case secrets will be missed and that old scrolled content may still contain secrets if the user manually scrolls up. The system prioritizes **practical risk reduction** over theoretical perfection.

---

## 3. Implementation Summary (v1)

**Core Architecture Delivered**

- **Explicit Protected Mode** (`br-start` / `br-stop`): User consciously enters a recording context. All work outside this mode is transient and never appears in rebuilds.
- **Go PTY Recorder** (`recorder/recorder.go`): Purpose-built long-lived PTY with inner `zsh`. Maintains atomic `RecordingWindow` buffers. Exposes control socket commands: `NEW_WINDOW`, `FLUSH_WINDOW`, `REPLAY_REDACTED`, `STOP`.
- **Automatic Window Management** (zsh `precmd`): On every prompt boundary while `BR_PROTECTED=1`, the current window is flushed and a new one is started.
- **Immediate Hashing Invariant**: Every line returned by `FLUSH_WINDOW` is treated as IO. It is hashed (via daemon `check-hash`) before any further processing. No secret value ever lives in memory beyond the transient recorder buffer.
- **Redacted Rebuild** (`blastradius_clear` / `br-clear`): Wipes the terminal, then calls `REPLAY_REDACTED`. The recorder emits a redacted stream (`[REDACTED]` for known secrets, original text otherwise). Only protected-mode content appears.
- **Zsh Layer**: Manages mode state, status display, socket communication (`zsocket`), and safe degradation when the recorder is unavailable.

**Key Design Decisions Upheld**

- No cross-window terminal state transfer.
- Recorder owns capture lifecycle; Zsh only orchestrates.
- All invariants (hash-only, minimal metadata, local-only, safe degradation, secrets-as-IO) remain intact.

This implementation fully realizes the "Explicit Protected Recording Windows" paradigm described in the high-level overview.

---

## 3. Core Philosophy & Invariants (Reinforced)

All previous invariants remain in force. The following are especially relevant to Phase 4:

- **Hash-only by construction** — Plaintext secrets are I/O only. They are hashed at the earliest possible moment and never retained.
- **Eliminate attack surface rather than reduce it** — The recording layer and rebuild process must not create new high-value artifacts.
- **Minimal metadata** — Session history stores only what is required for rebuild and detection.
- **Safe degradation** — If detection or rebuild fails, the system must fail safely (clear HUD warning, no silent incorrect state).
- **Composability over enforcement** — All functionality is exposed as composable Zsh functions and config options. The user controls the aggressiveness.
- **Non-interference during active use** — The original command output must be fully visible and unaltered while the user is interacting with it.

---

## 4. Architecture Overview (Hybrid Model)

### High-Level Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Terminal 1 (Zsh)                      │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────┐ │
│  │   Recording  │──▶│  Local Session   │◀──│  Rebuild     │ │
│  │   Layer      │   │  History Buffer  │   │  Engine      │ │
│  └──────────────┘   └──────────────────┘   └──────────────┘ │
│         │                    │                    ▲          │
│         ▼                    ▼                    │          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                    Unix Domain Socket                   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Go Daemon (Singleton)                     │
│  ┌──────────────────┐  ┌──────────────────────────────┐     │
│  │ Secret Hash      │  │ Analysis & Detection Engine  │     │
│  │ Registry         │  │ (receives candidates)        │     │
│  └──────────────────┘  └──────────────────────────────┘     │
│  ┌──────────────────┐  ┌──────────────────────────────┐     │
│  │ Cross-terminal   │  │ Configuration Service        │     │
│  │ Features (future)│  │                              │     │
│  └──────────────────┘  └──────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Hybrid Model Rationale (Trade-off)

**Why not put everything in the Go daemon?**

- Rebuild logic runs on every prompt cycle (or after buffer). Round-tripping to the daemon for every rebuild would add unnecessary latency and complexity.
- Per-terminal isolation is simpler when the history buffer lives locally in Zsh.

**Why not put everything in Zsh?**

- The Secret Hash Registry must remain in the daemon (single source of truth, consistent with Phases 0–3).
- Cross-terminal features (future) require a central point.
- Analysis can be offloaded to the daemon, keeping the Zsh hot path lightweight.

**Chosen Model**: Zsh owns per-terminal session history + rebuild engine. Daemon owns global registry + analysis. This gives the best balance of performance, resilience, and alignment with existing architecture.

---

## 5. Key Design Decisions & Trade-offs

### 5.1 Recording Layer: Managed `script` (Initial) vs Go PTY

**Decision**: Start with managed system `script` command for v1. Consider migrating to `github.com/creack/pty` in a later iteration.

**Rationale**:

- `script` already captures everything we need (full typescript with colors, escape sequences, control characters).
- Faster to validate the end-to-end flow.
- Lower initial complexity.
- Trade-off: Slight external process overhead and need to manage typescript (or use named pipes for lower latency). Acceptable for v1.

### 5.2 Detection Strategy (v1)

**Decision**: Simple structural + prefix + length-based candidate extraction. No entropy calculation in v1.

**Rationale**:

- Most real secrets in developer workflows appear after `=`, inside quotes, or start with known prefixes.
- Entropy calculation is more expensive than SHA-256 for short strings and adds little value at this stage.
- Target: ~95% coverage of common cases. We explicitly accept missing some edge cases.
- Full details in Section 6.

### 5.3 Rebuild Trigger & Frequency

**Decision**: Config-driven via `blastradius clear` entrypoint.

- `automated: true` + `buffer: N` (default N=1)
- `automated: false` → user calls `blastradius clear` manually

**Rationale**:

- Single function (`blastradius clear`) is the source of truth for all rebuild behavior.
- Gives users full control while still allowing automatic operation.
- Buffer of 0 = immediate (before output prints) — allowed but noted as potentially surprising.

### 5.4 What Gets Rebuilt

**Decision**: The entire session history up to `history_length`.

**Rationale**:

- `history_length` and rebuild scope are the same setting. Keeping them unified simplifies mental model and configuration.

### 5.5 Multi-Terminal Isolation

**Decision**: Hybrid — Zsh manages per-terminal history buffers locally. Daemon tracks sessions at a high level for analysis only.

**Rationale**:

- Performance (rebuild is local).
- Resilience (one terminal dying doesn't affect others).
- Still allows future cross-terminal features via the daemon.

---

## 6. Secret Detection Strategy (v1)

### 6.1 Layered Pipeline (High-Level)

1. **High-Risk Command Context**
   - Commands: `printenv`, `env`, `set`, `cat .env*`, `printenv | grep`, and user-configurable additions.
   - Action: Treat entire output as high-risk; extract candidates aggressively.

2. **Structural Candidate Extraction**
   - After `=` (right-hand side)
   - Inside single or double quotes
   - Tokens starting with known prefixes: `aws_`, `ghp_`, `gho_`, `Bearer`, `token=`, `key=`, `secret=`, `password=`, `apikey`, `auth`, etc.
   - Combine last word of line N + first word of line N+1 (simple multi-line handling)

3. **Cheap Filters**
   - Minimum length: 12–16 characters (configurable)
   - Basic sanity (contains alphanumeric characters)

4. **Hash + Registry Lookup**
   - Hash candidates with SHA-256
   - Send to daemon for lookup against Secret Hash Registry

### 6.2 What We Explicitly Do NOT Do in v1

- No Shannon entropy calculation
- No full multi-line secret reconstruction
- No external tool calls (TruffleHog, Gitleaks) in the default path
- No attempt to detect every possible secret format

**Trade-off**: Simplicity and speed vs. theoretical maximum coverage. We chose simplicity.

---

## 7. Session Management & Multi-Terminal Isolation

- Each Zsh instance maintains its own in-memory ring buffer: `[]HistoryEntry`
- `HistoryEntry` = `{Command, RedactedOutput, Timestamp, Metadata}`
- When a terminal exits, its buffer is discarded (no persistence in v1).
- The Go daemon maintains a lightweight map of active sessions (PTY or session ID → metadata) for analysis routing only.

**Security Note**: Session history never leaves the local machine and is never written to disk in plaintext.

---

## 8. The `blastradius clear` Rebuild Engine

This is the single most important function in Phase 4.

**Responsibilities**:

1. Clear the calling terminal only (`clear` / `reset` / escape sequences).
2. Replay the redacted session history from the local buffer (preserving ANSI colors by default).
3. Update HUD state.
4. Reset internal "pending sensitive" flags.
5. Respect `history_length` (drop old entries if needed).

**Composability**:

- Can be called automatically (after buffer) or manually by the user.
- Can be composed into prompt functions, keybindings, or other tools.
- User can choose which features are active (alerting, line deletion, full rebuild, color preservation, etc.).

---

## 9. Composability Model

All functionality is exposed as:

- Zsh functions: `blastradius clear`, `blastradius-secure-refresh`, `blastradius-prompt-info` (extended), etc.
- Config options (see Section 11).
- CLI commands: `blastradius clear`

The user can mix and match behaviors. There are no "levels" — only composable features.

---

## 10. Data Models (High-Level)

**HistoryEntry**

```go
type HistoryEntry struct {
    Command        string
    RedactedOutput string    // Never contains plaintext secrets
    Timestamp      time.Time
    Metadata       map[string]string
}
```

**SessionState** (per Zsh)

```go
type SessionState struct {
    ID           string
    History      []HistoryEntry
    PendingAlert bool
    Config       SessionConfig
}
```

**SecretCandidate** (sent to daemon)

```go
type SecretCandidate struct {
    Value  string
    Source string // "after_equals", "in_quotes", "prefix_match", etc.
    Line   int
}
```

---

## 11. Configuration Schema (Proposed)

```yaml
redaction:
  automated: true
  buffer: 1 # 0 = immediate, 1 = next command, etc.
  history_length: 0 # 0 = keep forever, otherwise drop after N entries
  preserve_colors: true
  show_rebuild_evidence: true # HUD message after rebuild

detection:
  high_risk_commands: ["printenv", "env", "set", "cat .env*"]
  min_candidate_length: 12
  aggressive_unknown: false # Flag high-entropy strings not in registry

clear_reset_commands: ["clear", "reset", "tput reset"] # Auto-reset internal history
```

---

## 12. Security Considerations

**Attack Surface Introduced by Phase 4**:

- Recording layer (managed `script`) captures terminal output.
- In-memory session history contains redacted (but still potentially sensitive) context.

**Mitigations**:

- Recording only happens when the user has enabled stronger protection.
- Plaintext secrets are never stored — only hashes or already-redacted text.
- Session history is in-memory only (no disk persistence in v1).
- Daemon runs with normal user privileges.
- All IPC is over local Unix domain socket with `0600` permissions.
- Safe degradation: if rebuild fails, terminal is cleared and a warning is shown.

**Threat Model Alignment**:

- Local attacker with user-level access: We do not make their job meaningfully easier (no new high-value artifacts, no plaintext storage).
- Accidental user exposure (original primary threat): Significantly reduced via rebuild + history scrubbing.

---

## 13. Implementation Order (Recommended)

1. **Foundation** — Managed `script` recording layer + per-terminal session buffer in Zsh.
2. **Detection** — Structural candidate extraction + daemon lookup integration.
3. **Core Rebuild** — `blastradius clear` function (clear + replay redacted history).
4. **Trigger Logic** — Config-driven buffer + manual invocation.
5. **Composability & Polish** — HUD integration, config system, clear/reset command handling, history trimming.
6. **Testing & Hardening** — Multi-terminal scenarios, long sessions, color fidelity, failure modes.

---

## 14. Risks & Mitigations

| Risk                                      | Likelihood | Impact | Mitigation                                               |
| ----------------------------------------- | ---------- | ------ | -------------------------------------------------------- |
| Visible flicker on rebuild                | High       | Medium | Acceptable for v1; only happens on actual secret leaks   |
| Missed multi-line secrets                 | Medium     | Medium | Documented limitation; focus on common single-line cases |
| Performance on very long histories        | Medium     | Medium | `history_length` + automatic trimming                    |
| Color/formatting loss on rebuild          | Low        | Medium | Preserve ANSI codes during replay (priority)             |
| PTY/session tracking bugs                 | Medium     | High   | Start with managed `script`; validate thoroughly         |
| User confusion about when rebuild happens | Medium     | Low    | Clear documentation + HUD evidence option                |

---

## 15. Future Work (Post-v1)

- Go-native PTY implementation (`github.com/creack/pty`) for lower latency.
- Entropy + more sophisticated pattern detection (optional aggressive mode).
- Cross-terminal secret correlation.
- Deeper terminal emulator integration (iTerm2, VS Code).
- Encrypted / persistent session history (with user consent).
- Plugin system for custom detectors.

---

**End of Phase 4 Design Document v1.0**

This document captures the complete design rationale, trade-offs, and decisions from the extended tech spike. All choices were made to balance ambition with pragmatism while strictly upholding the project's core invariants.
