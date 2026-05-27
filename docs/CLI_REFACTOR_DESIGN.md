# CLI Refactor Design Document – Single Coordinator Architecture

**Status:** Final Design (Ready for Implementation)
**Date:** 2026-05-25
**Author:** Synthesized from full conversation with user

---

## 1. Executive Summary

This document defines a comprehensive refactor of the Blast Radius CLI layer. The goal is to establish a **single, stable, user-facing CLI** as the only entry point for both humans and the Zsh integration layer. This CLI acts as a coordinator that owns:

- Daemon lifecycle management
- Per-terminal recorder lifecycle management
- Unified state surfacing for humans and Zsh

The design resolves long-standing concerns around CLI fragmentation, Zsh verbosity, composability, security (environment variable leakage), and adherence to the project’s core principles (KISS, YAGNI, DRY, Rule-of-3, “earn your abstractions”).

All major architectural decisions were reached through an extended, iterative discussion. This document captures the final settled state, the justifications, and the phased implementation plan.

---

## 2. Background & Problem Statement

### Original Architecture (Pre-Refactor)

- `cmd/blastradius` acted as a thin dispatcher.
- Two distinct machine APIs existed: the daemon socket and the recorder control socket.
- Zsh held minimal state (`BR_PROTECTED`, `BR_SESSION_HAS_SECRETS`, `BR_RECORDER_SOCKET`) and performed direct socket communication.
- This created three informal interfaces: daemon commands, recorder commands, and Zsh functions/variables.

### Problems Identified

- Multiple CLIs / interfaces felt unintuitive (user referenced Bitcoin `bitcoin-cli` vs `bitcoind` model).
- Zsh layer grew to 382 lines, violating the “thinnest possible broker” goal.
- Environment variables leaked protected-mode state to every child process.
- Per-terminal vs global state ownership was unclear.
- Future composability and Pillar evolution were difficult to reason about.

---

## 3. Review of the Conversation & Key Decisions

The conversation progressed through several paradigms:

- **Paradigm A**: Recorder always tied to terminal lifetime, owns all per-terminal state. Zsh is pure formatting.
- **Paradigm B**: Recorder on-demand; Zsh holds minimal state (rejected on security and composability grounds).
- **Paradigms C, E, F**: Various creative extensions (shared memory, status library, capability tokens) — all rejected under KISS/YAGNI/Rule-of-3.
- **Paradigm D**: Introduced the idea of a dedicated coordinator/helper. Evolved into the final single-CLI model.

**Final Settled Position (User Confirmed)**

- A single CLI binary is the **only** entry point.
- The CLI controls daemon lifecycle and recorder lifecycle.
- The CLI surfaces all state to both humans and Zsh.
- Zsh talks exclusively through the CLI binary (no direct recorder socket access).
- TTY-derived deterministic socket paths solve per-terminal routing.
- `blastradius protection start/stop` explicitly control recorder mode.
- `blastradius redact` is protection-mode only.
- Automatic redaction logic remains inside the recorder.
- All commands requiring protection mode fail with a clear message when inactive.
- Clean break migration — no compatibility layer.

These decisions were reached after extensive discussion of security, composability, process count, and project principles. The Rule-of-3 was satisfied by the three consumers: Human/Zsh, Recorder, and Daemon.

---

## 4. Final Architecture

### 4.1 Components

| Component                           | Responsibility                                                                            | Lifetime                                                  | Notes                        |
| ----------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------- | ---------------------------- |
| **Coordinator CLI** (`blastradius`) | Single human/Zsh API, lifecycle control, routing, unified status                          | On-demand (invoked by user or Zsh)                        | Only entry point             |
| **Recorder**                        | PTY middleman, window buffering, redaction, `REPLAY_REDACTED`, automatic redaction timing | Started by `protection start`, exits on `protection stop` | Registers TTY-derived socket |
| **Daemon**                          | Global `SecretHashRegistry`, cross-terminal services                                      | Managed by CLI (manual start/stop)                        | Never auto-started by CLI    |

### 4.2 Per-Terminal Discovery (TTY Solution)

- Recorder registers its control socket using a deterministic path derived from the controlling TTY (e.g., `~/.local/state/blastradius/recorder-<tty-hash>.sock`).
- The coordinator, when invoked from a terminal, computes the same path and connects.
- If the socket does not exist, the recorder is considered not running for that terminal.
- This mechanism works whether the recorder is running or not and requires no environment variables in Zsh.

---

## 5. Command Surface (Final)

### Protection Mode Commands

- `blastradius protection start` – Starts recorder for current terminal
- `blastradius protection stop` – Stops recorder for current terminal
- `blastradius redact` – Protection-mode only. Clears screen and rebuilds with redacted content. Also triggered automatically by recorder after N prompts.

### Lifecycle Commands

- `blastradius start` – Starts the global daemon (manual only)
- `blastradius stop` / `halt` – Stops the global daemon

### Status & Information

- `blastradius status [--json]` – Single unified status command containing global + current-terminal protection state. Used by Zsh.

### Other Commands

- All existing commands (`duplicates`, `scrub-history`, `env`, `clipboard`, `logs`, `check-hash`, etc.) are moved into the coordinator.
- Commands that semantically require protection mode or daemon are guarded and fail with a clear message when inactive.

### Clear / Reset Behavior

- Core terminal clear/reset commands (`clear`, `reset`, `tput clear`, `tput reset` and common argument forms) are now automatically recognized by the recorder on flush and cause protected history to be reset.
- The public `blastradius clear` CLI command was removed (it was a legacy stub).
- `clear_reset_commands` in config is now additive only; the four core commands are mandatory.

---

## 6. Protection Mode Behavior

- Protection mode is **explicit** (`protection start/stop`).
- Commands requiring protection mode (`redact`, and any future session-specific commands) fail with a clear, non-zero exit message when the recorder is not active for the current terminal.
- No automatic daemon start.
- Zsh may optionally invoke `protection start` from `.zshrc` if desired (this replaces the old “automatic” flag concept).

---

## 7. Pillar Interaction (Confirmed)

- **Pillar 3 (Redaction)**: `redact` command lives in coordinator. Automatic trigger count and timing logic remains inside the recorder.
- **Pillar 4 & 5 (History & Runtime Hygiene)**: `scrub-history` and `env` remain globally available. `redact` (and protection-related commands) are gated by protection mode. (The legacy `blastradius clear` command was removed.)
- All other pillars only require protection-mode guards where appropriate.

---

## 8. Zsh Integration

- Zsh layer is reduced to thin formatting and prompt functions.
- All state is obtained via `blastradius status --json`.
- No direct recorder socket communication from Zsh.
- No `BR_PROTECTED` / `BR_SESSION_HAS_SECRETS` environment variables are required.
- This achieves the “thinnest possible broker” goal while preserving full composability for user prompts.

---

## 9. Migration & Phasing

### 9.1 Phase Combination Analysis

After careful review, the five phases are kept **separate** rather than combined. The primary reasons are:

- The refactor involves a **clean break** migration with no compatibility layer. Combining phases would increase risk of incomplete state during the cutover.
- Each phase has distinct deliverables, testing surfaces, and rollback points.
- The large scope of moving CLI infrastructure makes incremental, verifiable phases preferable to larger combined phases.
- Only Phase 1 and Phase 2 could theoretically be combined, but doing so would create an overly large first implementation step and delay early feedback on the TTY discovery mechanism.

**Recommendation**: Keep the five phases as defined below. Each phase should produce a working, testable increment.

### 9.2 Detailed Phased Plan

**Phase 0 – Design (Current State)**

- This design document is complete and approved.
- All architectural decisions, justifications, and constraints are captured.
- No code changes are made in this phase.

**Phase 1 – Coordinator Skeleton, TTY Discovery & Protection Lifecycle**

**Objectives**

- Establish the new coordinator as the single entry point.
- Implement TTY-derived per-terminal recorder discovery.
- Implement the core protection mode lifecycle commands.

**Detailed Tasks**

- Create the new coordinator package structure under `cmd/blastradius`.
- Implement deterministic TTY-to-socket path calculation (including hash or sanitization strategy).
- Add `protection start` command:
  - Computes socket path from current TTY.
  - Launches the recorder process with the correct socket path.
  - Verifies the recorder has registered successfully.
- Add `protection stop` command:
  - Computes socket path from current TTY.
  - Sends shutdown signal to the recorder.
  - Cleans up the socket file.
- Implement a centralized `protectionModeGuard()` helper function that all subsequent commands will use.
- Add basic error handling and user messaging for when the recorder is not running.
- Write unit tests for TTY path generation and guard logic.
- Update help text and command registration for the new `protection` subcommand group.

**Deliverables**

- Working `blastradius protection start` and `protection stop` commands.
- TTY discovery logic with tests.
- Protection guard helper ready for reuse.
- Updated CLI help output.

**Risks & Mitigations**

- TTY name variations across terminal emulators → Test on macOS Terminal, iTerm2, VS Code, and tmux.
- Socket file cleanup on abrupt termination → Use signal handling and `defer` cleanup in recorder.

**Phase 2 – Daemon Lifecycle, Unified Status & Redact Command**

**Objectives**

- Move daemon lifecycle ownership into the coordinator.
- Create the single unified `status --json` command.
- Implement the `redact` command with protection-mode guard.

**Detailed Tasks**

- Move `start`, `stop`, `halt`, and daemon-related status logic into the coordinator.
- Ensure the coordinator never auto-starts the daemon (explicit user action only).
- Design and implement the unified `status` command:
  - Collects global daemon state.
  - Collects current-terminal protection/recorder state (via TTY-derived socket if present).
  - Outputs both human-readable and `--json` formats.
- Implement `redact` command:
  - Protection-mode guard (fails with clear message if recorder not active).
  - Sends `REDACT` (or equivalent) to the recorder.
  - Handles screen clear + rebuild semantics.
- Extend recorder control protocol if needed to support the new `redact` action.
- Ensure `clear` and reset commands continue to forward correctly to the recorder.
- Add comprehensive tests for status output (especially JSON schema stability).
- Update all existing daemon-related CLI tests to target the coordinator.

**Deliverables**

- Working `blastradius start/stop` for daemon.
- Stable `blastradius status --json` containing global + protection state.
- Working `blastradius redact` command (protection-mode only).
- All daemon lifecycle tests passing under new coordinator.

**Risks & Mitigations**

- JSON schema changes breaking Zsh → Freeze the top-level keys early and document them.
- Status command performance when recorder is slow to respond → Implement short timeouts with graceful degradation.

**Phase 3 – Full Command Migration (Clean Break)**

**Objectives**

- Move every remaining command into the coordinator.
- Remove the old dispatcher entirely.
- Apply protection-mode guards consistently.

**Detailed Tasks**

- Migrate all existing commands into the coordinator:
  - `duplicates`, `scrub-history`, `env`, `clipboard`, `logs`, `check-hash`, `clear`, `help`, etc.
- Apply the protection-mode guard to any command that requires an active recorder session.
- Remove the old `main.go` dispatcher logic and any compatibility shims.
- Update command registration, flag parsing, and error handling to the new structure.
- Ensure every command that previously talked to the daemon or recorder now routes exclusively through the coordinator’s connection helpers.
- Add protection-mode error messages that are consistent and user-friendly.
- Run the full existing test suite and fix any breakage caused by the clean break.
- Delete or archive old dispatcher code.

**Deliverables**

- All user-facing commands working under the new coordinator.
- Old dispatcher removed.
- Protection-mode guards applied where required.
- Full test suite passing.

**Risks & Mitigations**

- Large surface area of moved code → Migrate command-by-command with tests after each migration.
- Inconsistent error behavior → Centralize error formatting and messaging helpers.

\*\*Phase 5

- Make Zsh call only the CLI binary.
- Remove all direct recorder socket usage and environment variable state from Zsh.
- Achieve the thinnest possible Zsh layer.

**Detailed Tasks**

- Update `zsh/blastradius.zsh`:
  - Replace all direct `zsocket` calls with calls to `blastradius status --json`, `blastradius redact`, etc.
  - Remove or deprecate `BR_PROTECTED`, `BR_SESSION_HAS_SECRETS`, and `BR_RECORDER_SOCKET` variables.
  - Simplify prompt functions to use only CLI output.
- Ensure `blastradius status --json` output is stable and fast enough for prompt use.
- Remove any legacy direct recorder socket handling code from Zsh.
- Test prompt rendering and hook behavior (`precmd`, `preexec`) under the new model.
- Update Zsh documentation and examples.

**Deliverables**

- Dramatically reduced Zsh layer (target: well under 100 lines focused purely on formatting).
- All Zsh functionality working exclusively through the CLI binary.
- No environment variable leakage of protected-mode state.

**Risks & Mitigations**

- Performance regression in prompt → Profile `status --json` calls and consider lightweight caching if needed.
- Loss of functionality during transition → Maintain a feature-parity checklist for Zsh.

**Phase 5 – Polish, Documentation & Final Validation**

**Objectives**

- Ensure production readiness.
- Update all documentation.
- Perform final validation and cleanup.

**Detailed Tasks**

- Implement consistent, high-quality error messages for all protection-mode failures.
- Ensure deterministic socket cleanup on `protection stop` and on recorder crash.
- Run full test suite, linting (`go vet`, `golangci-lint`), and coverage checks.
- Update `README.md`, `docs/CURRENT_STATE.md`, and any other references to reflect the new architecture.
- Update help text and man-page style documentation.
- Perform manual testing across multiple terminal types and Zsh configurations.
- Create a short migration guide for existing users.
- Tag the release and update version information if applicable.

**Deliverables**

- Production-ready coordinator CLI.
- Complete, up-to-date documentation.
- All tests and linters passing.
- User-facing migration guidance.

**Risks & Mitigations**

- Documentation drift → Treat documentation updates as first-class deliverables in this phase.
- Edge-case terminal behavior → Allocate explicit testing time for uncommon environments (remote SSH, containerized shells, etc.).

---

This expanded phasing section provides explicit tasks, deliverables, risks, and mitigations for each phase while maintaining the decision to keep the five phases separate.

---

## 10. Design Justifications (Summary)

- **Single CLI as only entry point**: Meets user requirement for one human API and satisfies Rule-of-3 (Human/Zsh + Recorder + Daemon).
- **TTY-derived discovery**: Solves per-terminal routing without environment variables or Zsh state.
- **Explicit protection mode**: Aligns with original Phase 4 design intent and avoids hidden state.
- **Automatic redaction logic stays in recorder**: Preserves recorder ownership of window state and timing.
- **Clean break migration**: Avoids duplicated routing logic and inconsistent behavior.
- **All Zsh interaction through CLI**: Achieves thinnest possible broker while maintaining security and composability.
- **No consideration of future pillars**: Keeps scope focused and prevents premature abstraction.

---

## 11. Risks & Mitigations

- Large CLI refactor → Execute in small, testable slices with early extraction of shared logic.
- Per-terminal routing correctness → Thorough testing across terminal emulators.
- Protection-mode guards → Centralize guard helper.
- Socket lifecycle → Ensure deterministic cleanup on `protection stop`.

---

## 12. Document Ownership

This design document is the single source of truth for the CLI refactor. Any future implementation must follow the decisions and phases outlined above. Changes to this architecture require an update to this document first.

**End of Design Document**
