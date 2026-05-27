# Prompt Capture Integration Plan – Making the Recorder's PTY Capture Real User Sessions

**Status:** Design Phase (Revised)  
**Date:** 2026  
**Related Documents:**
- `docs/CLI_REFACTOR_DESIGN.md`
- `docs/PHASE4_DESIGN.md`
- `docs/REDACT_N_PLAN.md`
- `zsh/blastradius.zsh` (current placeholder `precmd`/`preexec`)

---

**CRITICAL: THIS PLAN HAS BEEN REVISED BECAUSE THE PREVIOUS VERSION WAS WRONG.**

The previous version recommended treating the recorder primarily as a state machine driven from the outer shell via hooks, with the PTY being secondary. 

**That approach is rejected.**

The entire reason this system exists is to capture the user's actual terminal session — both the commands typed **and the full output that appeared on screen** — so that `blastradius redact` can later produce a redacted reconstruction of what the user actually saw. 

If an implementation only captures the commands the user typed and does not capture the output those commands produced, **it is a failure**. Full stop. "Command only" mode is not an acceptable MVP. It does not deliver the value proposition. 

`script(1)` proves the model works: create a PTY, run the user's shell inside it, and record everything that flows through that PTY. We already have exactly that machinery in `recorder.NewRecorder()`. The job is to make it actually own the user's real interactive session instead of sitting idle in the background.

---

## 1. Executive Summary & Goal

**The non-negotiable goal of this entire project is high-fidelity capture of the user's real terminal session (commands + output) for later redacted replay.**

Currently:
- `blastradius protection start` starts a recorder that creates a perfectly good PTY + inner zsh and has a `captureLoop` that can see everything written to that PTY.
- That PTY is completely disconnected from the user's actual terminal.
- The user's real commands and, more importantly, the **real output** those commands produced never enter the recorder.
- `blastradius redact` therefore has nothing useful to replay.

**Goal (non-negotiable)**: After `blastradius protection start`, when the user runs normal commands in their interactive shell, the recorder must capture:
- The exact command the user typed.
- The **actual output** that appeared on their terminal as a result of that command (including from external binaries, pipes, scripts, etc.).
- Automatic `RESET_HISTORY` behavior on clear/reset commands.

Only then can `blastradius redact` produce a redacted version of the actual session the user experienced.

**Failure condition**: Any implementation that only captures command strings while leaving output as empty or placeholder is a failure. It does not solve the problem this system was built to solve. "We'll add output later" is not acceptable. Output capture is the core requirement, not a stretch goal.

Post-refactor invariants (preservation of these is desirable but secondary to output capture fidelity):
- No `BR_PROTECTED` / `BR_RECORDER_SOCKET` leakage into child processes where possible.
- The `blastradius` binary remains the primary interface.
- The experience must remain usable.

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

## 3. Recommended Approach (Corrected)

**The recorder's PTY is the correct capture mechanism.** It was built for exactly this purpose. `script(1)` demonstrates the model: create a PTY, spawn a shell on it, and everything the user types and everything the commands emit flows through that PTY and can be recorded.

The previous plan's recommendation to treat the recorder as "primarily a stateful engine driven from the outer Zsh" and to avoid putting the user inside the recorder's PTY was a mistake. It leads to fragile, incomplete output capture.

**Correct Model**:

When protection is active, the user's interactive session must produce output that flows through the recorder's PTY (or an equivalent capture path that delivers equivalent fidelity).

Two viable paths exist. They must be evaluated against the non-negotiable requirement of real output capture:

**Path A (Preferred if achievable)**: Make `blastradius protection start` cause the user's real interactive shell to run inside the recorder's PTY.
- This is the `script`-like model.
- The `captureLoop` sees the actual bytes the user produced and received.
- `NEW_WINDOW` / `FLUSH_WINDOW` can still be used for logical windowing and clear/reset handling, but the raw data comes from the PTY.
- This delivers the highest fidelity.

**Path B (Fallback)**: The outer Zsh remains the user's shell, and high-quality output capture is achieved through other means (wrappers, redefinition of output builtins + side channels, `zsh/zpty` for command execution, etc.) that still feed faithful output into the recorder.

**Path A is strongly preferred** because it is the same mechanism that already works in `script` and that the PTY code was written to support. Path B should only be chosen if Path A proves impossible or unacceptably destructive to the user experience.

The "do not teleport the user into the PTY" guidance from the previous version of this plan is hereby **withdrawn**.

### 3.1 Non-Negotiable Requirements

1. **Output must be captured.** If `printenv | grep SECRET` runs under protection and the secret appears in the output, `blastradius redact` must be able to show a redacted version of that output. Command-only capture is not sufficient.
2. The recorder must see the real bytes that went to the user's terminal, not a best-effort reconstruction from the outer shell.
3. The solution must work for normal developer workflows (pipelines, external tools like `aws`, `curl`, `python`, `cat`, interactive tools where practical, etc.).
4. "We'll capture output later" or "command capture is a good start" are not acceptable positions. Output capture is the primary deliverable.

### 3.2 Key Technical Decisions

1. **PTY as Primary Capture Vehicle**
   - The existing `NewRecorder()` PTY + `captureLoop` should be the main source of truth for what the user saw.
   - The control protocol (`NEW_WINDOW`, `FLUSH_WINDOW`, etc.) is still valuable for logical session structure and clear/reset handling, but raw data should come from the PTY where possible.

2. **Process Model on `protection start`**
   - The central question is no longer "how do we make the outer shell feed data."
   - The central question is: "How do we make the user's interactive experience happen inside (or through) the recorder's PTY without making the tool unusable?"

3. **"Attach to existing shell" vs. Fidelity**
   - The desire to never replace or wrap the user's current shell process must be subordinate to the requirement to capture real output.
   - If perfect "zero change to process model" is incompatible with faithful output capture, the process model must change.

4. **No reliance on external `script`**
   - We will not shell out to or depend on the system's `script` command. We have our own PTY machinery for a reason. We must own the capture path.

---

## 4. Phased Implementation Plan

### Phase 0 – Make the PTY the Actual Capture Source (Foundation)

**Objectives**
- Stop launching an idle, disconnected PTY on `protection start`.
- Make the recorder's PTY the place where the user's real session actually executes (or the primary source of captured data).
- The `captureLoop` must see real user commands and real command output.

**Tasks**
- Change the behavior of `blastradius protection start` (and the recorder startup path) so that the PTY created by `NewRecorder()` is connected to the user's interactive experience.
- Decide between:
  - Exec/replace model: The current shell is replaced by one whose controlling terminal is the recorder's PTY.
  - Subshell/launch model: `protection start` launches a new protected zsh inside the recorder PTY that the user then works inside.
- Ensure that when the user types commands inside this PTY-backed shell, the `captureLoop` naturally receives the output (this should "just work" once the process model is correct).
- Keep the control socket for `REPLAY_REDACTED`, `RESET_HISTORY`, status, etc.
- The logical windowing protocol (`NEW_WINDOW` / `FLUSH_WINDOW`) can still be used (driven either from the inner shell's hooks or from the recorder itself) for clear/reset detection and window boundaries.
- Update `protection stop` to cleanly terminate the protected session.

**Deliverables**
- Running `blastradius protection start` results in the user's subsequent commands and their output actually being captured by the recorder's PTY.
- `blastradius redact` after normal work produces a redacted replay containing real output, not just commands.

**Risks**
- Process model / exec / controlling tty complexity.
- UX differences from "just staying in my current shell."

---

### Phase 1 – Zsh Integration as Supporting (Not Primary) Capture Layer

**Objectives**
- Zsh hooks are useful for logical markers (`NEW_WINDOW`, clear/reset detection, `RESET_HISTORY` signaling) but are **not** the primary mechanism for delivering output bytes.
- The real output must come from the PTY capture path.

**Tasks**
- Implement the thin Zsh layer for sending control commands (`NEW_WINDOW`, `RESET_HISTORY` when appropriate) over the TTY-derived socket.
- This layer is now secondary — it provides structure and policy (clear commands, etc.), while the PTY provides the raw data.
- Keep the "no env var leakage" and direct-socket (for control messages) discipline.
- Document clearly that output fidelity comes from the PTY, not from these hooks.

**Deliverables**
- Zsh can send the necessary control messages when protection is active.
- It is obvious in the code and docs that these hooks are not responsible for output capture.

---

### Phase 2 – Deliver Faithful Output Capture via the PTY Path

This is the hardest and most important phase.

**Objectives**
- The user's real commands and the real output they produce must flow through the recorder's PTY when protection is active.
- `blastradius redact` after normal work must be able to show redacted versions of actual command output, not just redacted command lines.

**Primary Focus**
- Solve the process model problem so that the PTY created in `NewRecorder()` becomes the controlling terminal for the protected interactive session.
- Once that is working, the `captureLoop` will naturally see the correct data. The problem largely reduces to "get the user inside the PTY" rather than "invent clever ways for the outer shell to ship bytes back."

**Secondary / Supporting Work**
- Use Zsh hooks inside the PTY-backed shell for `NEW_WINDOW`, clear/reset detection, and any logical markers.
- Evaluate whether any of the old techniques (B, D, etc.) are still needed as supplements for edge cases.
- Explicitly deprecate "command only" as an acceptable state.

**Deliverables**
- End-to-end working system where `blastradius protection start` followed by normal work, followed by `blastradius redact`, produces a redacted reconstruction that includes the actual output the user saw (with secrets replaced).
- Any implementation that only captures commands is rejected.

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

**Recorder / PTY integration (highest priority)**
- `recorder/recorder.go` — especially `NewRecorder()`, `captureLoop`, `RunControlServer`, and how protection start launches/attaches to it.
- The process model around `blastradius protection start` (currently in `internal/cli/protection.go` and `internal/cli/recorder.go`).

**CLI / lifecycle**
- `internal/cli/protection.go` — the actual behavior of `protection start` and `protection stop` is now the critical path.
- How the recorder process is launched and whether the user's shell ends up connected to its PTY.

**Zsh side (supporting)**
- `zsh/blastradius.zsh` — now primarily for sending logical control messages (`NEW_WINDOW`, clear detection) rather than being the source of output data.

**Tests & verification**
- End-to-end manual test matrix is now the most important validation: real commands with real output, pipelines, external tools, `redact` showing redacted output.
- Unit tests around PTY attachment and capture fidelity.

---

## 6. Major Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Failure to capture real command output (only commands are captured) | **Critical / Project Failure** | This is not acceptable. The PTY must be the source of truth for output. Any design that cannot deliver this must be rejected or fundamentally reworked. |
| Inability to give the user a usable interactive shell while capturing through the PTY | High | Evaluate exec vs. subshell launch models. Accept some UX difference if it is the price of correct capture. |
| Terminal / emulator / job control differences when running inside the recorder PTY | High | Heavy manual testing across common environments (Terminal.app, iTerm2, VS Code, tmux, ssh). |
| Breaking users' existing shell customizations | Medium | Document the supported model clearly. Provide escape hatches and a way to run an unprotected shell. |
| State drift between what the user saw and what was captured | High | The PTY is the source of truth by construction. Do not layer fragile reconstruction on top of it. |

---

## 7. Success Criteria (Pass/Fail)

**Mandatory (implementation is a failure without these):**

1. A user runs:
   ```zsh
   blastradius protection start
   printenv | grep SECRET
   aws sts get-caller-identity
   blastradius redact 0
   ```
   and `redact` produces output that includes redacted versions of the **actual command output** (not just the commands the user typed). Secrets that appeared in command output must be replaced in the replay.

2. Normal pipelines, external binaries, and common developer commands have their output captured with high fidelity.

**Strongly desired:**

3. `blastradius protection stop` cleanly ends the protected session.
4. Minimal or no leakage of protected-mode state into the environment / child processes.
5. The experience is usable for real work (even if the process model changes somewhat compared to an unprotected shell).
6. Limitations are clearly and honestly documented. "Output is not captured" is not an acceptable documented limitation for the primary use case.

## 7.1 Definition of Done / Exit Criteria (Explicit)

The work is **not complete** until all of the following are true:

- A user can run `blastradius protection start`, execute normal commands that produce output (including external programs and pipelines), then run `blastradius redact`, and see the command output present in the replay (with secrets redacted).
- The captured data for output comes primarily from the recorder's PTY `captureLoop`, not from hook-based reconstruction.
- Command-only capture is not the shipped behavior.
- The above works across the common environments the team actually uses.

---

## 8. Open Questions (to resolve before or during implementation)

1. **Process model**: Exec/replace the current shell into the recorder PTY, or launch a new protected subshell inside it? What is the least destructive usable UX?
2. How do we cleanly exit protection and return the user to a normal shell (`protection stop`)?
3. How do we handle job control, signals, terminal resize, and background jobs when the interactive shell is inside our PTY?
4. How do we support common environments (tmux, screen, iTerm2, VS Code integrated terminal, SSH sessions) without losing capture or breaking usability?
5. Is any hook-driven supplementation still required inside the PTY-backed shell, or does the PTY + logical window markers from the inner shell suffice?
6. How do we handle very large output in a single window (memory + protocol limits)?
7. Strategy for supporting bash/fish later.

---

## 9. Why This Is Worth Doing

The only reason this entire system (daemon, recorder, redaction engine, `blastradius redact`, etc.) exists is to let people work normally and later produce a redacted version of what actually appeared on their terminal.

If we cannot capture real output, the feature is a lie. The PTY we already wrote is the correct tool to solve this. The job now is to stop launching it as an idle background process and make it the actual environment the user works inside when they say `protection start`.

Anything less is not delivering the product.

**End of Plan**
