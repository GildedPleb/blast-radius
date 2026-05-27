# Implementation Plan: `redact N` — Resolving the Limitation While Upholding All Invariants

**Status:** ✅ Implemented (historical record)  
**Date:** 2026-06 (post CLI refactor)  

> This plan was fully implemented. See `bug.md` for resolution summary and code for the actual realization of Phases A–E. All tests, invariants, and UX goals were met.
**Related:** [bug.md](../bug.md) (the documented limitation), [docs/CLI_REFACTOR_DESIGN.md](CLI_REFACTOR_DESIGN.md), [docs/PHASE4_DESIGN.md](PHASE4_DESIGN.md), [docs/CURRENT_STATE.md](CURRENT_STATE.md)  
**Goal:** Deliver first-class `blastradius redact [N]` (and automatic future-policy support) without relaxing any security, memory, or reliability invariants.

---

## 1. Executive Summary

The core tension documented in `bug.md` is real: a naive `redact N` (last N prompts replayed with original/raw output containing secrets; everything older redacted) appears to require either (a) unbounded plaintext in the recorder, (b) fragile terminal-specific scrollback manipulation, or (c) accepting that already-visible history cannot be perfectly retrofitted.

**This plan resolves the limitation by unifying two previously separate concepts (`buffer` and raw retention) into one explicit, user-controlled value.**

- The existing `redaction.buffer` setting (default: **1**) now controls both automatic redaction timing *and* how many recent windows keep their full raw output.
- On every flush, windows that age out of the current `buffer` value are **sealed** (raw secret material and `Secrets` slices are discarded; only a redacted representation remains).
- `REPLAY_REDACTED` is extended to accept an optional `N`. The replay produces a mixed stream: redacted forms for older history + raw original for the most recent `min(N, buffer)` windows (when raw is still available).
- The `blastradius redact [N]` CLI command (previously a stub) performs a reliable full clear + mixed replay.
- All invariants are **strengthened**, not relaxed. Plaintext lifetime is now strictly bounded by the (configurable) `buffer` value.
- Default of 1 is retained (current behavior). Users who want more aggressive sealing ("secrets gone on the very next prompt") can set `buffer: 0`.

Users who want high-fidelity `redact 2` / `redact 3` behavior explicitly raise `buffer` (and thereby accept the corresponding bounded memory exposure for that many recent windows). The system never surprises them with unbounded accumulation of raw secret material.

---

## 2. Consolidated Invariants (Must Be Preserved)

These are drawn from Phase 0 foundations, PHASE4_DESIGN.md, CURRENT_STATE.md, README.md, bug.md, and code comments. Any solution that violates any of them is unacceptable.

### Security / Data Lifetime Invariants (Hard)

1. **Registry never contains plaintext.** Only SHA-256 hashes of secret *values*. (Daemon side — unchanged.)
2. **No secret material (plaintext or hashes) ever written to disk.** Config, logs, sockets, state files, history files, etc. all remain clean.
3. **IPC is local-only, 0600 Unix domain sockets.** Both daemon and per-terminal recorder sockets.
4. **True singleton daemon + per-TTY recorder isolation.**
5. **Plaintext secret lifetime in memory is minimized and bounded (recorder-specific strengthening of "secrets as IO").**
   - Only the live `RecordingWindow.Buffer` (current command in flight) may hold raw output containing secrets.
   - Completed windows retain raw secret bytes for **at most** the current `buffer` value.
   - The instant a window ages past the `buffer`, its `Lines[].Raw` (and `Secrets`) are replaced by sealed redacted content; original secret bytes become unreachable for GC.
   - The exposure is always explicit, small, and automatically shrinks as new commands arrive.
6. **Eliminate attack surface rather than reduce it.** The recent-raw buffers are the highest-value artifact the recorder creates. Bounding them + automatic sealing is the correct mitigation. Long-running protected sessions must not accumulate an ever-growing hoard of historical plaintext.

### Functional / Correctness Invariants

7. **Non-interference during active use.** The user always sees 100% original, unaltered command output for the command they just ran (until the next prompt boundary and any subsequent automated or manual rebuild).
8. **Full clear + replay is the only reliable redaction mechanism.** No cursor math, no selective scrollback overwrites, no terminal-emulator-specific escape sequences for partial history redaction. (Full `tput clear` / `\033[2J\033[3J\033[H` style wipes + replay are acceptable and already the documented approach.)
9. **Safe degradation.** If the recorder socket is gone, daemon is down, or replay fails, the terminal must be cleared with a clear warning rather than leaving potentially secret material visible. Status must accurately reflect reality.
10. **Minimal metadata + opaque identifiers.** No unnecessary paths or identifying material in any in-memory structures.
11. **Composability.** `redact [N]` (and the underlying replay) must be callable from Zsh, keybindings, scripts, and the human CLI with stable behavior.
12. **History trimming still works.** `redaction.history_length` (0 = unbounded) continues to hard-cap the total number of retained windows (redacted or raw).

### Non-Goals / Explicit Trade-offs We Accept

- When a user requests `redact 5` but `buffer=2`, the last 2 will be original; windows 3–5 (within the requested N) will appear redacted in the rebuilt view. This is the best possible fidelity under the memory invariant. The implementation must communicate this clearly.
- Pre-redacted historical windows use the redaction mode that was current at sealing time (usually the configured default). Runtime mode changes primarily affect windows still holding raw.
- We do **not** attempt to "unredact" content that has already scrolled out of the retention window.

---

## 3. Core Solution Architecture

### 3.1 Unified Retention via the Existing `buffer` Setting

**Decision**: `redaction.buffer` and the raw retention window **are the same setting**. There is no separate `raw_retention_windows` knob.

- The existing `buffer` value (default: 1) now controls both:
  - How many prompts must pass after a secret-containing command before automatic redaction/rebuild is allowed.
  - How many of the most recent windows we keep full raw output for (so that `redact N` and automatic rebuilds can still show originals for recent commands).
- When a window ages past the current `buffer` value, it is immediately sealed (raw secret bytes and `Secrets` are discarded; only the redacted form remains).
- User can set `buffer: 0` for aggressive behavior ("seal the window on the very next prompt after the command finishes").

Example (unchanged from today, now with clearer semantics):

```yaml
redaction:
  buffer: 1          # Default. Raw kept for the most recent 1 window.
                     # Set to 0 for "immediately sealed on next prompt".
                     # Set to 2 or 3 if you want `redact 2` / `redact 3` to be useful.
  history_length: 0
  ...
```

- The value is live-reloaded on every flush (same pattern already used for `history_length`).
- Exposed in `status --json` (as `buffer` plus derived `current_raw_windows`).
- The help text for `blastradius config redaction` and the example config must clearly explain that this value directly controls plaintext lifetime in the recorder.

### 3.2 Data Model Changes (`recorder/types.go`)

```go
type Window struct {
    StartTime time.Time
    Command   string
    Lines     []Line
    HasSecret bool

    // Sealed redacted form for windows that have aged out of the current `buffer` value.
    // When non-nil / non-empty, this window no longer contains any secret plaintext.
    RedactedCommand string   // redacted or original if no secret
    RedactedLines   []string // always safe to emit; produced with default mode at seal time
}
```

`Line` can stay as-is (raw + spans only present while the window is still inside the current `buffer` value).

Alternative (slightly simpler for GC): keep using `Lines` for raw while within retention; when sealing, set `Lines = nil` and populate the two new `Redacted*` fields. `HasSecret` remains forever for `remove_cmd` decisions.

### 3.3 Retention / Sealing Enforcement Logic (in `recorder/recorder.go`)

The raw retention logic is now driven directly by the existing `buffer` value (no separate `raw_retention_windows` field).

Implement / rename as:

```go
func (r *Recorder) enforceBufferRetention() {
    buf := r.getCurrentBuffer()   // live from config.Redaction.Buffer (default 1)

    if buf <= 0 {
        // Aggressive (buffer: 0): seal every completed window on the next flush.
        for i := range r.recent {
            r.sealWindow(r.recent[i])
        }
        return
    }
    if len(r.recent) <= buf {
        return
    }
    // Seal windows that have aged past the buffer.
    sealUpTo := len(r.recent) - buf
    for i := 0; i < sealUpTo; i++ {
        r.sealWindow(r.recent[i])
    }
}
```

`sealWindow()` is unchanged in purpose (build redacted representation using the default mode, discard `Lines` + secret bytes, retain `HasSecret` + redacted text for future replays).

Call `enforceBufferRetention()` at the end of `FlushCurrentWindow`, after history trimming.

The `sealWindow()` implementation itself is unchanged from the earlier description (it builds the redacted representation, discards the raw secret material, etc.).
    if len(w.RedactedLines) > 0 {
        return // already sealed
    }

    mode := r.getDefaultRedactionMode() // from live config or constant
    custom := r.getDefaultCustomReplacement()

    if w.Command != "" {
        if spans := findSecretSpans(w.Command); len(spans) > 0 {
            w.RedactedCommand = string(applyRedaction([]byte(w.Command), spans, mode, custom, true))
        } else {
            w.RedactedCommand = w.Command
        }
    }

    for _, ln := range w.Lines {
        if len(ln.Secrets) == 0 {
            w.RedactedLines = append(w.RedactedLines, string(ln.Raw))
        } else {
            red := applyRedaction(ln.Raw, ln.Secrets, mode, custom, true)
            w.RedactedLines = append(w.RedactedLines, string(red))
        }
    }

    // Discard the secret material
    w.Lines = nil
    // Spans inside the (now unreachable) Line structs will be GC'd.
    // The original []byte backing the old Raw slices become unreachable.
}
```

Call `enforceRawRetention()` at the end of `FlushCurrentWindow` (after the history_length trim) and also from `StartNewWindow` / on config reload paths.

The effective buffer value is refreshed from config on every flush (cheap).

### 3.4 Extended Replay (`recorder/redaction.go` + handler)

Update signature:

```go
func (r *Recorder) handleReplayRedacted(w io.Writer, requestedRecent int, mode, custom string, preserveColors bool)
```

Logic (inside the lock):

- `effectiveN := min(requestedRecent, currentBuffer, len(r.recent))`
- For i, win := range r.recent:
  - ageFromEnd := len(recent)-1-i
  - if ageFromEnd < effectiveN && len(win.Lines) > 0 {
      // still has raw → emit original command + original lines (respect remove_cmd only if policy says so? per bug semantics: last N are always original)
      emitRaw(win)
    } else {
      // use sealed redacted (or on-the-fly if not yet sealed for some reason)
      emitRedacted(win, mode, custom, preserveColors)
    }
- The `remove_cmd` mode only affects the redacted portion (older windows). The "keep last N original" windows are emitted in full even if they contained secrets. This matches the documented desired semantics.

Handler (`recorder/handlers/replay_redacted.go`) parses an optional leading integer from the payload (backwards compatible; absence or 0 means "full redaction").

New wire format examples:

```
REPLAY_REDACTED
REPLAY_REDACTED 3
REPLAY_REDACTED 2 replace [REDACTED] true
```

### 3.5 CLI Implementation (`internal/cli/`)

- Add `redact` case to `cmd/blastradius/main.go`.
- Implement `RunRedact(args []string)` in `internal/cli/clear.go` (rename or keep file).
  - ProtectionModeGuard()
  - Parse optional N (default 0)
  - Load config for redaction settings + clear commands
  - Perform reliable terminal clear:
    - Try configured `clear_reset_commands` (tput, clear, etc.)
    - Always emit a strong ANSI clear + scrollback clear: `\033[2J\033[3J\033[H`
    - This is the accepted, reliable mechanism (not a "hack").
  - Open connection to the TTY-derived recorder socket (new helper `sendRecorderCommand` in `conn.go` or `recorder_conn.go`).
  - Send `REPLAY_REDACTED <N> <mode> <custom> <preserve>`
  - Stream everything until `OK\n`, printing to stdout (this is what the user sees after the clear).
  - On error: clear again + print safe warning.
- Add `sendRecorderCommand` (modeled on `sendDaemonCommand`, but uses the per-TTY socket from `getRecorderSocketPath()` and short timeouts).

### 3.6 Status & Observability

Extend the JSON output in `RunStatus` (when recorder socket exists) to include:

```json
"recorder": {
  "active": true,
  "socket": "...",
  "buffer": 2,
  "current_raw_windows": 2,
  "current_raw_windows": 1,
  "total_windows": 14,
  ...
}
```

This makes the memory exposure visible and auditable.

---

## 4. Phased Implementation Plan

Keep phases small and independently testable (following the spirit of the CLI refactor phases).

### Phase A — Foundation (Config, Types, Sealing Logic) — No user-visible behavior change

- Update `internal/config/config.go`: add field + default (0) + docs.
- Update `recorder/types.go`: add `RedactedCommand` / `RedactedLines`.
- Implement `sealWindow` + `enforceRawRetention` + config reload in `recorder/recorder.go`.
- Call the enforcer at end of `FlushCurrentWindow`.
- Add unit tests in `recorder/recorder_test.go` and new `retention_test.go`:
  - With retention=0, after flush, `recent[i].Lines == nil` and `Redacted*` populated; original secret strings no longer appear in the struct.
  - With retention=2, exactly the last 2 retain `Lines`/`Secrets`; older ones are sealed.
  - History length trim interacts correctly with sealing.
- Update `config_test.go` and example config.
- **Deliverable**: Recorder never retains more raw history than configured. All existing tests still pass. Zero behavior change for current `REPLAY_REDACTED` (N=0 path).

### Phase B — Protocol & Replay Engine

- Extend `ReplayRedactedHandler` and `handleReplayRedacted` to parse and honor `N`.
- Implement mixed emit logic (raw for recent-within-bound, sealed redacted otherwise).
- Update `recorder/handlers/context.go` interface if needed (probably just extend the existing `ReplayRedacted` method).
- Add handler tests (`replay_redacted_test.go` updates or new).
- Recorder-level tests that exercise the socket with N > 0 and verify output contains raw secrets only for the requested recent count (and only if retention allowed it).
- **Deliverable**: `REPLAY_REDACTED 3` (when retention >=3) produces correct mixed output over the control socket.

### Phase C — CLI Surface (`blastradius redact [N]`)

- Wire `redact` in `main.go`.
- Implement full `RunRedact` (guard + clear + recorder socket round-trip + streaming replay).
- Add `sendRecorderCommand` helper (and test double support like the daemon one).
- Make the clear logic respect `config.redaction.clear_reset_commands` + always do a strong ANSI wipe.
- Update `clear.go` help / `RunClear` documentation.
- Add CLI tests (extend `cli_test.go` or new `redact_test.go` using the test recorder harness patterns already present).
- **Deliverable**: `blastradius redact` and `blastradius redact 2` work end-to-end from the human CLI when protection is active. `blastradius redact` without protection fails cleanly.

### Phase D — Integration, Zsh, Status, Polish

- Update `zsh/blastradius.zsh`: `blastradius_redact() { _blastradius redact "$@"; }` (already almost there).
- Expose `buffer` and `current_raw_windows` (derived from buffer) in `status --json` (and human status).
- Update `internal/cli/status.go`.
- Update `config.go` `RunConfig` to document the new field.
- Update all design docs + `CURRENT_STATE.md` + `README.md` security posture section.
- Add a short "Redaction Retention" section to the user guide / help.
- **Deliverable**: Full vertical slice works from Zsh hooks → CLI → recorder. Status makes the memory bound visible.

### Phase E — Hardening, Documentation, Release

- Cross-terminal manual testing (Terminal.app, iTerm2, VS Code, tmux, SSH) for the clear + replay experience.
- Add a soft high-water-mark warning (see TODO.md) if total windows or estimated retained raw bytes exceed thresholds.
- Security-focused test: a long running protected session with many secret-containing commands; assert via white-box inspection that only the last K windows can possibly contain secret material.
- Update `bug.md`: mark the limitation as resolved by this plan; add pointer to the new doc.
- Write migration / configuration guidance for users who previously relied on the informal "recorder keeps everything" behavior.
- Run full test suite + coverage + `go vet` / linters.
- **Deliverable**: Production-ready feature, all invariants explicitly upheld in code and docs, limitation closed.

---

## 5. Files Expected to Change

| File | Changes |
|------|---------|
| `docs/REDACT_N_PLAN.md` | This document (becomes historical record after implementation) |
| `bug.md` | Update status, add "Resolved by RETENTION PLAN" link |
| `internal/config/config.go` | No new field. Update documentation and help text for `buffer` to explain it now also controls raw retention / plaintext lifetime. |
| `config.example.yaml` | Expand the comment on `buffer` to explain its dual role (automatic timing + raw retention bound) and security implications |
| `recorder/types.go` | Add `RedactedCommand` / `RedactedLines` to `Window` |
| `recorder/recorder.go` | `enforceBufferRetention()` (driven by existing `buffer`), `sealWindow()`, call sites in FlushCurrentWindow, live config reload of buffer |
| `recorder/redaction.go` | Updated `handleReplayRedacted` + helper that knows raw vs sealed |
| `recorder/handlers/replay_redacted.go` | Parse optional N prefix, forward it |
| `recorder/handlers/context.go` | Possibly widen `ReplayRedacted` signature |
| `internal/cli/clear.go` | Real `RunRedact` implementation (clear + socket roundtrip) |
| `internal/cli/main.go` (cmd) | Wire the `redact` top-level command |
| `internal/cli/conn.go` | `sendRecorderCommand` (and test var) |
| `internal/cli/status.go` | Include retention numbers in JSON + human output |
| `internal/cli/paths.go` | Possibly small helpers |
| `internal/cli/*_test.go` + `recorder/*_test.go` | New tests for retention, sealing, mixed replay, CLI redaction |
| `zsh/blastradius.zsh` | Thin wrapper for `blastradius_redact` with args |
| `docs/CURRENT_STATE.md`, `PHASE4_DESIGN.md`, `README.md` | Update architecture snapshots and invariant tables |
| `internal/cli/help.go` | Mention `redact [N]` |

---

## 6. Testing Strategy (Especially Invariant Verification)

This is the most important part of the plan. "We upheld the invariant" must be mechanically verifiable.

1. **White-box retention tests** (highest priority)
   - Create a recorder, emit 10 windows containing a known secret string ("AKIAIOSFODNN7EXAMPLE").
   - With `buffer=0`, assert that *none* of the completed windows in `r.recent` contain the secret string in any `[]byte`, `Command`, or `Raw` field after their flush. Only `Redacted*` fields may contain the replacement text.
   - With `buffer=2`, assert exactly the last 2 windows still contain the secret bytes; older ones have been sealed.
   - After more flushes, the sliding window of retained raw material moves forward correctly and old secrets disappear.

2. **Replay fidelity tests**
   - With retention=2 and 8 windows (some with secrets), request `REPLAY_REDACTED 2` and assert the returned stream contains original secret text exactly in the final 2 command blocks and nowhere earlier.
   - Request `REPLAY_REDACTED 5` (when buffer=2) and assert it behaves as `2` + emits a warning line or structured note that can be observed by the caller.

3. **Default-is-strict test**
   - Fresh recorder (no config override) must behave as retention=0.

4. **Integration / CLI tests**
   - Use the existing test harness patterns (`testhelpers_test.go`, handler test contexts) to drive a recorder over a real socket, call the CLI `redact` entrypoint (with test doubles for the clear side effects), and inspect both the terminal output and the post-replay recorder state.

5. **Memory / GC hygiene (optional but valuable)**
   - After sealing, force GC and use runtime/metrics or a test hook to show the backing arrays for old raw buffers are no longer referenced (best-effort).

6. **Cross-mode interaction**
   - `remove_cmd` + N still works (older secret windows omitted, recent N shown raw).
   - `history_length` trim + retention sealing compose correctly.

All new tests must pass with `-race`.

---

## 7. UX & User Communication

- `blastradius redact` → full redaction rebuild (identical to today's behavior).
- `blastradius redact 3` → "sanitize everything except the last three prompts".
- When protection is off: clear error + suggestion to run `protection start`.
- When requesting N larger than the current `buffer`: the replay still succeeds but is capped; the CLI should print a clear note ("Note: buffer is currently 1; only the most recent 1 prompt can be shown unredacted").
- `blastradius status --json` makes the current exposure visible to scripts and the HUD.
- Config help and example file contain a prominent security note:
  > "The `buffer` setting controls how many recent command outputs (including any secrets) are kept in raw form inside the recorder process. This is required for `redact N` fidelity and for the automatic redaction grace period. Higher values increase the window during which a memory dump or compromised recorder could see those values. Default 1 is the recommended balance."

- Zsh users doing automatic rebuilds can call `blastradius redact $BR_REDACT_RECENT` or hard-code a small number.

---

## 8. How This Directly Addresses the Scenarios in `bug.md`

**Scenario: `redact 2` after secrets have already appeared (8 commands run)**

- With default `buffer: 1`: `redact 2` is capped at 1. The most recent window can still be shown raw; everything older (including most of the "last 2") will come from sealed redacted forms. This is the honest behavior under the unified setting.
- If the user has `buffer: 2` (or higher), then `redact 2` can show the last two blocks with their original raw output, while commands 1–6 use the sealed redacted forms. The first time a window ages past the current `buffer`, its raw bytes are sealed and become unrecoverable — invariant preserved.

**Scenario: Live redaction for future output**

- The `buffer` value continuously governs both automatic rebuild timing and raw retention. New windows age out of the raw window exactly when they age out of the automatic redaction buffer. Future `redact N` calls (manual or automatic) can only show raw for windows still inside the current `buffer`. Perfect.

No terminal hacks are used. The full clear + replay remains the mechanism.

---

## 9. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Users set very high retention and are surprised by memory use | Medium | Default 0; prominent docs + status visibility; optional soft warning in recorder when >10 windows retained raw |
| Sealing logic has off-by-one and leaks one extra window | Low | Exhaustive white-box tests + property-based checks on the sliding window |
| Clear + replay flicker or scrollback not fully cleared on some terminals | Medium (existing) | Keep the existing pragmatic approach; document that "best effort" scrollback clearing is acceptable; offer `BR_CLEAR_EXTRA` escapes if users need them |
| Config change while recorder is running doesn't affect in-flight windows | Low | Document that retention changes take effect on next flush; live reload already works for history_length |
| Test coverage gap on the "sealed vs raw" decision | Low | Make the retention tests part of the gate for Phase A/B |

---

## 10. Open Decisions (for Reviewer / User Input)

1. **Should `redact N` when `N > buffer` be rejected, silently capped, or emit a warning + use `min(N, buffer)`?** Recommendation: cap with a clear message to the user.
2. **Should `redact N` persist a session policy?** Current plan treats N as per-invocation (simple, matches existing `REPLAY_REDACTED` payload style). A separate `blastradius redact --set-recent 2` could be added later if wanted.
3. **Should the sealed redacted form re-apply colors / zsh %F codes or stay as plain text?** Current `applyRedaction` behavior when `preserveColors=true` is fine.
4. **Expose `buffer` + current raw window count more prominently in the HUD?** Status --json already surfaces it; Zsh prompt integration is optional.

---

## 11. Success Criteria

- All existing tests + new retention & mixed-replay tests pass (including race detector).
- With default `buffer: 1`, a long protected session leaves raw secret material for at most the single most recent window. Setting `buffer: 0` leaves zero completed windows with raw secret material after their flush.
- `blastradius redact 2` (when retention allows) produces a terminal view whose last two prompt blocks are byte-for-byte identical to what the user originally saw, while everything above is redacted.
- Status JSON and docs make the memory bound completely transparent.
- `bug.md` can be updated to say the limitation has been resolved under a controlled, invariant-preserving design.

---

**End of Plan**

This plan delivers the originally desired `redact N` capability while turning the previous informal tension into an explicit, bounded, auditable, and default-strict policy. All project invariants are not merely "not violated" — they are actively enforced and made visible by the implementation.
