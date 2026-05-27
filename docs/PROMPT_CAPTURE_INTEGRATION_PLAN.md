# Prompt Capture Integration Plan – Driving the Recorder from Outer Zsh

**Status:** Design Phase  
**Date:** 2026  
**Related Documents:**
- `docs/CLI_REFACTOR_DESIGN.md` (the "largest remaining item" explicitly called out)
- `docs/PHASE4_DESIGN.md`
- `docs/REDACT_N_PLAN.md`
- `zsh/blastradius.zsh` (current placeholder `precmd`/`preexec`)

---

## 1. Executive Summary & Goal

The single largest piece of work remaining after the CLI refactor is to make **protected mode actually capture the user's real interactive session**.

Currently:
- `blastradius protection start` launches a recorder process with its own idle inner PTY zsh.
- The recorder exposes a clean control protocol (`NEW_WINDOW`, `FLUSH_WINDOW`, `RESET_HISTORY`, `REPLAY_REDACTED`, ...).
- `blastradius redact` and `status --json` work against this recorder.
- However, **no actual user commands or output ever reach the recorder** because the outer interactive Zsh (where the user lives) does not drive the protocol on prompt boundaries.

**Goal**: When a user runs `blastradius protection start` inside their normal shell and then runs normal commands, the recorder should receive:
- The exact command the user typed (via `NEW_WINDOW`)
- The output produced by that command (via `FLUSH_WINDOW`)
- Automatic `RESET_HISTORY` on clear/reset commands
- So that a subsequent `blastradius redact` produces a useful redacted rebuild of the actual session the user saw.

This must be done while preserving the post-refactor invariants:
- No `BR_PROTECTED` / `BR_RECORDER_SOCKET` leakage into child processes.
- The `blastradius` binary remains the primary human + status interface.
- High-frequency prompt hooks must be cheap (direct socket access is acceptable for capture; everything else goes through the CLI).

---

## 2. Current Architectural Reality (The Core Problem)

### 2.1 The PTY Middleman vs. "Attach to Existing Shell"

The recorder (`recorder/recorder.go:NewRecorder`) does two things:
1. Creates a real PTY + spawns an inner `zsh` and runs a `captureLoop` that writes PTY output into `RecordingWindow.Buffer`.
2. Exposes a Unix socket control protocol that drives logical `Window` objects via `StartNewWindowWithCommand` + `FlushCurrentWindow`.

When `protection start` is invoked from an already-running interactive shell:
- It execs a completely separate `blastradius recorder start` process.
- That process's inner PTY is never connected to the user's terminal.
- The user's keystrokes and command output never appear in the capture buffer.

The control protocol handlers (`NewWindowHandler`, `FlushWindowHandler`) operate on the logical `recent` slice of `Window`s. In practice today, the PTY buffer is largely unused for real protected sessions started via the CLI.

This is the central tension that any plan must resolve.

### 2.2 What the Hooks Must Do (Intended Flow)

From comments in the current `zsh/blastradius.zsh` and earlier designs:

- `preexec`: Send `NEW_WINDOW <full command line about to execute>`
- `precmd`: Send `FLUSH_WINDOW` (and possibly `RESET_HISTORY` if the command was a clear)
- The recorder becomes the owner of the protected history window state + redaction + replay logic.
- `redact` continues to work by calling `REPLAY_REDACTED` over the same TTY-derived socket.

---

## 3. Recommended Approach (Pragmatic Path)

**Do not** attempt to make the user's existing interactive shell "teleport" into the recorder's PTY at runtime. This is extremely difficult, terminal-emulator dependent, and violates the "attach to whatever shell the user is already in" requirement.

**Recommended Model**:

Treat the **recorder primarily as a stateful redaction + replay engine**, not as a passive PTY sniffer for the main user shell.

- The **outer interactive Zsh** (the one the human is typing in) becomes the authoritative source of commands and output for protected sessions.
- On prompt boundaries it notifies the recorder (via the already-computed TTY-derived Unix socket) using the existing control protocol (with small, targeted extensions if needed).
- The recorder's internal PTY + `captureLoop` is kept for:
  - Future "launch a fully isolated recorded shell" use case (`blastradius protection exec` or similar).
  - Backward compatibility / debugging.
  - But it is **not** the primary data path for normal `protection start` usage inside an existing shell.

This aligns with the post-CLI-refactor philosophy: the outer Zsh is thin but **not** brain-dead for the one thing it must do well (prompt-boundary observation).

### 3.1 Key Technical Decisions (to be confirmed or adjusted)

1. **Output Delivery on Flush**
   - Preferred: Extend the protocol so the caller can supply the observed output when calling `FLUSH_WINDOW`.
     - Example: `FLUSH_WINDOW <length>\n<raw bytes>` or a new `RECORD_OUTPUT <data>` followed by `FLUSH_WINDOW`.
   - Alternative: Keep `FLUSH_WINDOW` parameter-less and have the Zsh send output via a separate channel. Less clean.

2. **Direct Socket vs. CLI Passthrough for Hooks**
   - High-frequency calls (`preexec`/`precmd` on every command) **must** use direct Unix socket access from Zsh (`zsocket` module or `socat`/`nc` one-shot).
   - We explicitly document this as the narrow, accepted exception (already done in the current zsh file).
   - The CLI binary is used for `protection start/stop`, `redact`, `status --json`, and any human-facing operations.

3. **Detecting "Protected Mode Active" from Zsh Without Env Vars**
   - Use a lightweight cache (file or variable with short TTL) populated from `blastradius status --json`.
   - Or simply attempt the socket connection and fail fast if the recorder isn't there for this TTY.
   - Goal: zero leakage of protected-mode state into `printenv`, child processes, etc.

4. **Command vs. Full Output Capture (MVP slicing)**
   - MVP can start with reliable **command capture** + placeholder output. This already gives value for history hygiene and some redaction use cases.
   - Full faithful output replay is the stretch goal that makes `redact` "magical".

---

## 4. Phased Implementation Plan

### Phase 0 – Protocol & Recorder Surface Hardening (Foundation)

**Objectives**
- Make the control protocol friendly to an external driver that supplies output.
- Ensure the recorder can operate in "externally driven" mode vs. "PTY driven" mode cleanly.

**Tasks**
- Add support for supplying output data with `FLUSH_WINDOW` (or introduce `RECORD_LINES` / `FLUSH_WINDOW` sequence).
  - Update `FlushWindowHandler` and `FlushCurrentWindow` to accept optional payload.
  - Keep backward compatibility for any existing direct callers.
- Add a `RECORD_COMMAND_OUTPUT` or similar if separating concerns is cleaner.
- Ensure `RESET_HISTORY` remains idempotent and safe to call from hooks.
- Add a recorder mode / flag or detection so that when windows are driven externally, the internal PTY captureLoop can be a no-op or disabled for that session.
- Add unit tests that drive the recorder purely through the control protocol (no PTY involved).
- Update `RecorderContext` interface if needed (probably not).

**Deliverables**
- Protocol documented in a small `docs/RECORDER_PROTOCOL.md` or in the recorder package.
- Recorder works correctly when driven 100% from the outside.

**Risks**
- Protocol churn. Mitigate by keeping the simple parameter-less forms working.

---

### Phase 1 – Minimal Zsh Hook Surface + Direct Socket Helper

**Objectives**
- Give the outer Zsh the ability to talk to the recorder for its own TTY cheaply and reliably.
- Implement the thinnest possible "am I protected for this TTY?" check.

**Tasks**
- In `zsh/blastradius.zsh`, implement a small internal function that:
  - Computes (or caches) the TTY-derived recorder socket path using the same algorithm as Go (`getRecorderSocketPath` logic must be replicated or called via a fast CLI helper).
  - Provides `_br_recorder_send <command> [payload]` using `zsocket` (preferred) or a fallback one-shot connector.
- Add `blastradius_protection_status` (or rely on `status --json` with a fast path).
- Implement skeleton `preexec` and `precmd` that:
  - Check (cheaply) whether protection is active for this TTY.
  - If yes: on `preexec` send `NEW_WINDOW $1` (or the full preexec args).
  - On `precmd` send `FLUSH_WINDOW` (initially with no data or a marker).
- Handle the case where the recorder socket disappears (protection was stopped externally) gracefully.
- Add a config or env toggle (`BR_DISABLE_HOOKS` or similar, carefully) for debugging.

**Important Sub-task**: Replicate or expose the TTY-to-socket hash algorithm so Zsh can compute the exact same path the Go side uses. This is critical for the "no env var" model.

**Deliverables**
- Zsh can successfully send `NEW_WINDOW` and `FLUSH_WINDOW` when protection is active.
- No breakage for users who are not in protected mode.
- Clear comments explaining the direct-socket exception.

---

### Phase 2 – Reliable Command + Output Capture in Zsh

This is the hardest phase.

**Objectives**
- Capture the command the user actually typed (relatively easy via `preexec`).
- Capture the output that appeared on the terminal as a result of that command (hard).

**Tasks & Techniques to Evaluate**

**Command Capture (easy)**
- Use the `preexec` hook's arguments. Zsh provides the command in a very clean form here.

**Output Capture Options** (need prototype + measurement):

A. ** zle + POSTDISPLAY / temporary PS1 tricks**  
   Limited; works better for short output.

B. **Redefine `print`, `echo`, `printf` inside protected sessions** (with `unfunction` on exit).  
   Surprisingly effective for many cases, but misses subprocess output and `cat` etc.

C. **Use `script -q -f -` or `unbuffer -p`** as a lightweight wrapper when entering protection.  
   The outer Zsh can detect this and adjust. Gives a clean stream that can be fed to the recorder.

D. **Zsh `zsh/zpty` module** to create a controlled pty for the "work" the user does.  
   Most powerful but also most complex and has its own edge cases.

E. **Accept "command + exit status + duration" only** for v1, and treat output as "unknown" (redact still clears on `redact`, but cannot faithfully replay prior output).  
   Honest degradation.

F. **Send output as part of the next `NEW_WINDOW` or on `precmd` by reading the terminal scrollback** (very terminal dependent, fragile).

**Recommended for the plan**: Prototype options B and C first (they have the best effort/reward ratio). Document the chosen technique(s) and their limitations clearly.

Also implement automatic `RESET_HISTORY` when the flushed command matches the clear/reset policy (can be done in Zsh or let the recorder's existing `isClearResetCommand` logic catch it if we send the command name correctly).

**Deliverables**
- Working end-to-end: user types commands in a protected shell → `redact` shows a useful (even if imperfect) redacted reconstruction.
- Clear documentation of capture fidelity and limitations.

---

### Phase 3 – Polish, Safety, Performance, and Edge Cases

- Latency: Measure the cost of the socket calls on every prompt. Add optional async or coalescing if needed.
- Nested protection / re-entrancy.
- Long-running commands (background jobs, `sleep`, editors) – when does the window flush?
- Multi-line commands, `eval`, `source`, here-documents.
- Correct handling of `setopt` changes, `PROMPT_SUBST`, etc.
- Interaction with existing `precmd`/`preexec` functions the user may already have (use `add-zsh-hook` or at least document the requirement).
- Performance under very rapid command execution (arrow-up history replay, etc.).
- Error handling and safe degradation: if the recorder is slow or dies, the user's shell must not become unusable.
- Update `blastradius status` to surface "hook driver connected" or last flush time if useful.
- Add integration / manual test instructions (the hardest kind of test to automate).

**Deliverables**
- Production-quality hook code with good comments and error resilience.
- Updated user documentation and migration notes.
- The feature is no longer "the largest remaining item."

---

### Phase 4 – Optional / Future

- A `blastradius protection exec` mode that *does* launch the user's shell inside the recorder PTY (for users who want the original middleman model).
- Richer metadata per window (timing, exit status, working directory, duration).
- Optional per-command hashing of output lines sent to the daemon (as originally envisioned in some Phase 4 designs).
- Support for other shells (bash, fish) via their respective hook mechanisms.

---

## 5. Critical Files & Components

**Zsh side (primary new work)**
- `zsh/blastradius.zsh` – the real implementation of the hooks + socket helper.

**Recorder / protocol side**
- `recorder/recorder.go` (handleConn, FlushCurrentWindow, possibly new methods)
- `recorder/handlers/flush_window.go` and related
- Possibly a small protocol documentation file.

**CLI side (thin support)**
- Possibly new subcommands under `blastradius recorder` for debugging (`new-window`, `flush-window`, `reset-history`).
- Or just document direct use of the socket for advanced users.

**Tests & verification**
- New recorder tests that are purely control-protocol driven.
- Extremely thorough manual test matrix (different terminals, tmux, nested shells, long output, binary output, clear commands, etc.).
- Possibly a small "record-and-replay" harness for automated testing of the Zsh hooks.

---

## 6. Major Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Unreliable / incomplete output capture | High | Be honest in docs and UI. Provide "command-only" mode as a safe baseline. Multiple capture strategies with fallback. |
| Prompt latency / sluggish shell | Medium-High | Direct socket only (no CLI binary per prompt). Measure and optimize. Optional disable. |
| Terminal / emulator differences | High | Heavy manual testing. Accept that some fancy terminals (iTerm2 image protocol, etc.) may not replay perfectly. |
| Breaking users' existing precmd/preexec | Medium | Use `add-zsh-hook` if possible, or very clear load-order documentation. Provide escape hatches. |
| Protocol instability during development | Medium | Version the protocol messages early or keep simple text forms stable. |
| State drift between what the user saw and what the recorder thinks happened | High | The "source of truth" must be the outer Zsh's observation of its own output. |

---

## 7. Success Criteria

1. A user can do:
   ```zsh
   blastradius protection start
   printenv | grep SECRET
   some-other-command
   blastradius redact 0
   ```
   and see a redacted version of the actual session (with secrets replaced) instead of an empty or stale replay.

2. `blastradius protection stop` cleanly stops capture.
3. No environment variables are leaked.
4. The experience feels "it just works" for common developer commands.
5. The implementation is maintainable and the limitations are clearly documented.

---

## 8. Open Questions (to resolve before or during implementation)

1. Exact wire format for supplying output on flush (length-prefixed binary? base64? separate messages?).
2. Which output capture technique in Zsh gives the best fidelity/complexity ratio for v1?
3. Should we still start the inner PTY at all on `protection start`, or only when using an explicit "exec" mode?
4. How do we handle very large output in a single window (memory + protocol limits)?
5. Do we want to expose a "raw passthrough" mode for power users who want to feed arbitrary data?
6. Strategy for supporting bash/fish later (or explicitly scoping to Zsh only for this feature).

---

## 9. Why This Is Worth Doing

This is the piece that makes the entire Pillar 3 (redaction) story real for everyday interactive use, rather than a manual "start recorder + somehow drive it" experience. Completing it fulfills the original promise of the Phase 4 / redaction work in the context of the cleaner post-refactor architecture.

Once this is done, the system has a credible "enter protected mode, work normally, later scrub your terminal history" workflow.

**End of Plan**
