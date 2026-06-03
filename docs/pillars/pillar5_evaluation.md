# Pillar 5 Evaluation — Clipboard Hygiene

**Date:** 2026 (systematic review, post Pillar 4 update)
**Scope:** Full implementation audit against the telos in `docs/pillars/idiomatic_pillars.md`, cross-referenced with `CURRENT_STATE.md`, `config.example.yaml`, code (cli/clipboard.go + supporting), tests, zsh layer, daemon protocol, detection, P3 redaction reuse potential, and sibling Pillar 4 (`env` primitive). Special attention to the declared-but-unimplemented auto-clear timer (`clear_seconds`) and the philosophical/design questions raised about its shape.
**Method:** Static code review (all call sites, data flows, duplication with P4), behavioral tracing (pbpaste/pbcopy paths, candidate extraction, batch CHECK_HASH + AUTH), comparison of P1 registration vs hygiene detection, test execution (`go test ./internal/cli -run 'Clipboard'` + full `./...`), doc/consistency checks, failure mode enumeration, first-principles story writing (ideal behaviors, not "what the current 30s declaration implies").

> **Note:** This document captures the state after the "Pillar 4 update" commit (which also hardened the shared CHECK_HASH loop patterns in clipboard.go and env.go). The auto-clear timer remains unimplemented; the evaluation treats the *declared surface* (config, docs, idiomatic telos) as part of what must be judged against the heart of the pillar.

---

## Telos (from idiomatic_pillars.md)

**Pillar 5 — Clipboard Hygiene**
- **Purpose**: Catching and limiting secrets that have reached one of the most dangerous single-copy surfaces on a developer machine.
- On macOS, the clipboard is an extremely high-blast-radius location.
- This pillar *detects* when known secrets land in the clipboard and *can automatically clear them after a configurable time*.
- **Core question it answers**: "Has a secret made it into the one place that makes it trivial to paste into the wrong window, chat, or AI prompt?"

Summary table positions it as: "Limit damage on the highest-risk copy surface" / "Single dangerous clipboard".

Contrast with Pillar 4 (the closest sibling):
- P4 is explicitly "a primitive function call" (`blastradius env [name]`): run a configured introspection command, search its output via unified detector + registry, surface count only, log result. No timers/hooks in the primitive itself.
- P5's declared telos includes both the detection primitive *and* an automatic time-based limiting behavior.

---

## Implementation Overview

- **Config**: `internal/config/config.go` — `Pillar5Config` with RedactTimeoutSeconds (default 30), FullClearTimeoutSeconds (default 60), RedactPlaceholder (default "[REDACTED]"), MonitorEnabled, AlertsEnabled (no legacy single-timer support, dropped as alpha). Two independent user-configurable timeouts for story 5 two-tier auto + configurable placeholder piped to redaction (manual + auto). Monitor/alert toggles. Prefer pillar5.redact_placeholder over pillar3 for clipboard. normalizePillar5 ensures default.
  - Detailed in `config.example.yaml` matching the 5 targeted stories + fast first-secret alert + intentional use window example.
  - `CURRENT_STATE.md` updated to reflect monitor + scrub + two-tier + status exposure (stories 1-5 captured).
- **CLI entry**: `internal/cli/clipboard.go:RunClipboard(args)`.
  - Subcommands: status/check (story 1 visibility), scrub/redact (story 2, pbpaste+extract+replace using P3 placeholder + pbcopy), clear (story 3 blunt).
  - `pbpaste` (direct exec) → ExtractCandidates → batch CHECK (socket) for known. Scrub does in-place redaction.
  - Report JSON with secrets_found or action/redacted count.
  - macOS-only for v1.
- **Daemon monitor + state (stories 4+5)**: `internal/daemon/daemon.go` runs `runClipboardMonitor` (if enabled) on ticker. On change: Extract + Has; **alert on first known secret** (fast path, non-blocking) then full count. Two-tier: redact after redact_timeout (P3 replace), full clear after full_clear (if stable hash epoch). State (count, last_change, redacted/cleared, monitor_active) via Pillar5ClipboardStatus exposed in STATUS under pillar5.clipboard. Logs + best-effort osascript/afplay alerts.
- **Observability**: `pillar5.clipboard` in daemon STATUS (JSON + partial human in cli/status). Manual primitives update clipboard (monitor sees on next tick).
- **Daemon side**: Only `CHECK_HASH` handler (thin pass to `registry.IsKnownHashHex`). The multi-CHECK pattern over one conn (after initial AUTH line) is explicitly supported for "the Pillar 4 env primitive and clipboard".
- **Detection**: Shared `internal/detection/detector.go:ExtractCandidates` (same as P2/P3/P4). Line-aware, structured JSON, prefix patterns (Bearer, token= etc.), assignment RHS, broad fallback, entropy+len+noise gates.
- **Clear action**: Blunt. No inspection, no redaction, no "only if secret present". Always empties the pasteboard.
- **Zsh**: Thin `blastradius_clipboard() { _blastradius clipboard "$@"; }` wrapper only. No prompt integration, no auto.
- **Direct-exec invariant**: Upheld for pbpaste/pbcopy (called out in CURRENT_STATE invariants #9). Matches P4's hard rule.
- **Tests**: `internal/cli/clipboard_test.go` (good coverage of branches: no cands, cands+known, daemon not running, pbpaste fail, clear, unknown, full net.Pipe conn+AUTH+multi-CHECK paths, auth-skip). Uses same test override harness as env. Full suite passes.
- **Duplication**: ~the batch CHECK/AUTH/reader loop is duplicated with env.go (both recently hardened for write/read errors in the Pillar 4 update). No shared helper yet.
- **Redaction reuse**: P3's `internal/scrub/policy.go` (`ApplyToLine` / `ApplyBatch` + `ModeRedact`, `strings.ReplaceAll` of confirmed secret values, placeholder) is not used by P5. The logic is close to what a "redact secrets in clipboard" would need (but P3 works on pre-fetched `known map[[32]byte]bool`; clipboard paths do per-cand wire checks).

---

## Does It Meet the Letter and Heart of the Purpose (Telos)?

**Partial — the observation + blunt-clear primitives work and are consistent with the "hygiene function call" model; the automatic limiting story and redaction story are absent or under-specified.**

- **Positive (letter of core job)**:
  - `blastradius clipboard` / `check` / `status` *does* read the live clipboard via direct `pbpaste`, runs it through the unified post-2026 detector (robust candidate extraction for real-world pastes: exports, curl headers, KEY=val blocks, JSON, Bearer tokens, free text), batches CHECK_HASH over one conn, and reports a clean count of *known* secrets without ever emitting values.
  - `clear` provides an immediate "nuke the board" escape hatch using direct `pbcopy`.
  - Direct-exec invariant upheld (no shell).
  - Uses the same detector as every other hygiene surface (good).
  - Error paths are reasonably safe (daemon not running → "unknown"; pbpaste fail → explicit macOS message; partial CHECK failures log but continue and may undercount).
  - Test surface is strong (net.Pipe exercises the exact AUTH + multi-CHECK wire protocol the daemon supports for hygiene callers).
  - Recent hardening (Pillar 4 update) brought clipboard's CHECK loop to parity with env on error logging/continuance.

- **Gaps vs heart / stated purpose**:
  - **The automatic time-based hygiene ("can automatically clear them after a configurable time") is pure vaporware**, exactly as `AutoOnPrompt` was for P4 at the time of its evaluation. `ClearSeconds` exists, defaults to 30, is documented as future, but is **never read anywhere**. No timer, no watcher goroutine (in CLI or daemon), no polling of pbpaste, no "on secret sighting, start decay" logic. The telos and config declare a proactive limiting behavior that does not exist.
   - However, the *spirit* of proactive hygiene can be delivered first (and more safely) via the event-driven reactive alert system: the daemon watcher detects the copy/change event and *immediately surfaces an alert* (notification/audible/toolbar). This gives the user the awareness at the critical moment without having to guess intent or auto-destroy. The monitor is the "proactive" piece that was missing, and it aligns better with the gray space than a pure timer-to-clear ever could.
  - **"Clear" is too blunt and always-on**. It does not inspect first. It does not prefer redaction (P3-style in-place secret removal that preserves the rest of the user's copied material). It does not condition on "secret was present". Unconditional full clear destroys non-secret content the user may have intentionally placed on the clipboard alongside (or instead of) a secret. This is the exact concern that prompted this review: "we should not be clearing every 30 seconds no matter what it is. In fact, I don't even think we should be clearing it all."
  - **No redaction path at all for the live clipboard surface**. P3 invested heavily in `mode: redact` + placeholder + receipt machinery precisely because full deletion loses user intent and command shape. Clipboard (a single mutable blob that users often copy *structured* content into) has higher value for partial cleanup. The absence is a missed opportunity for "least surprise + maximum utility" hygiene.
  - **The primitive is not framed or documented like Pillar 4's**. P4's docstring and help emphasize "primitive function call", "the function does one thing only; timers/prompt wiring are later." P5's `RunClipboard` and help text are more casual ("status / clear"). The check path is the direct analog of `RunEnvCheck`, but it is not elevated to the same "this is the safe introspection of the clipboard surface *right now*" story.
  - **(Historical gap, now addressed for targeted stories)** Zero observability... (see updated Implementation Overview: monitor + Pillar5ClipboardStatus + human/JSON now provide live count/last_change/auto flags for stories 4+5).
  - **Zsh / prompt layer has no P5 visibility** (only P1 count via status). No equivalent of "suggest running clipboard check after a dirty env".

**Verdict on telos (post-capture of 5 targeted stories)**: The 5 stories (1 visibility primitive, 2 redact/scrub primitive, 3 blunt clear, 4 reactive fast-alert on first secret, 5 two-tier grace auto with independent configurable redact/full-clear timeouts) are now implemented (primitives in CLI, monitor+alert+auto+state in daemon, config support, status exposure, reuse of detection/P3 placeholder). Meets the "inform + provide escape + optional auto" heart better than old single-timer model. Remaining per eval recs: shared helper dupe cleanup, more tests/seams for monitor, full P3 reuse, doc consistency (in progress in this capture), P1-detector gate (systemic). (Capture work executed per the approved plan in the session plan.md.)

---

## Leaks (Secret Material Exposure or Missed Detections)

1. **Systemic false-negative leak (cross-pillar, inherited by P5)**: Identical to the #1 leak called out in the Pillar 4 evaluation. P1 (scanner.go `processEnvFile` / `collectHashesFromFile`, bitwarden collector) registers *any* non-empty, non-ignored-key value (notes has a weak `len(notes) > 8`). Hygiene paths (P5 included) route through `Detector.ExtractCandidates` → `isPlausibleSecret` (MinLen=8, MinEntropy=4.0, !isCommonNoise which drops short strings containing "secret"/"password" etc.). Result: short, low-entropy, or "noisy" secrets that the user deliberately stored in legitimate P1 sources **will be in the registry but will never be extracted as candidates from clipboard (or env/history/residue)**, so P5 silently fails to detect exposure of exactly the material it claims to protect. This is architectural debt between "ground truth registration" and "live surface detection."

2. **Materialization of clipboard content in CLI process (and potentially daemon for future auto)**: `pbpaste` output is fully materialized as `[]byte` before any candidate extraction or early return. If the clipboard contains megabytes (rare but possible: whole config files, large JWTs + context, base64-encoded blobs), it lives in RAM. For the duration of the CHECK loop, confirmed secret *values* also exist as Go strings in the candidates slice and during the loop. On crash/coredump/swap/inspection of the `blastradius clipboard` process, material is exposed. (Unavoidable for the model — the surface must be read to be protected — but worth stating. No streaming or bounded read.)

3. **Clear path has no "was there a secret?" observability**: The clear subcommand never calls pbpaste or detection. It just runs pbcopy. If a user (or future auto) does `clear` and there *was* a secret, we have no log line saying "cleared N known secrets". The only log is the generic "RunClipboard: clearing clipboard". Post-clear, there is no way to know whether the action was a hygiene win or a no-op.

4. **AUTH / partial CHECK undercounting (same as P4)**: If AUTH token read fails or a mid-loop socket error occurs, subsequent candidates are skipped (with log), `found` undercounts, but final JSON is still `status:ok` with the (low) number (or `known:false` if zero). User may believe "0 found" when the check was incomplete. (Daemon-not-running is correctly "unknown"; partial failures inside a live conn are the subtle case.)

5. **Test logging side effects**: Same as P4 — every test path that reaches the top of `RunClipboard` calls `logging.Init(getDaemonLogPathFn())`, which in normal runs targets the *real* `~/.local/state/.../daemon.log`. The resetTestOverrides dance mitigates but does not eliminate the global logger concern for CLI hygiene.

6. **No size / sensitivity limits on the inspected surface**: A user (or compromised process, or cat of a huge file) can put an enormous blob on the clipboard. P5 will pbpaste it all, run the full (somewhat expensive) candidate extraction with multiple regex + JSON parse + broad tokenization passes, then do N socket roundtrips. No truncation, no early abort on first known secret, no byte limit.

---

## Errors, Bugs, and Failure Modes

1. **Code duplication with P4 (structural, not a runtime bug)**: The manual dial + optional AUTH write (no read of AUTH resp) + per-candidate CHECK_HASH + single `bufio.Reader` + loose `strings.Contains(resp, `"known":true`)` + "count may be incomplete" logging lives in two places. The Pillar 4 update made both more robust, but the duplication means future auth protocol changes, reader handling improvements, or batching (e.g. a proper `BATCH_CHECK_HASH` or chunked responses) must be applied twice. P4 eval already recommended a shared `batchCheckHashes(conn, cands) int` helper.

2. **Loose response parsing (same as P4)**: `strings.Contains(resp, `"known":true`)` works for the current handler output but is fragile to whitespace, pretty-print, added fields, or future changes to the JSON shape from `CheckHashHandler`. (Note: the handler returns compact `map` marshaled; current daemon path does not pretty-print.)

3. **Clear subcommand ignores all other args and never inspects**: `blastradius clipboard clear --redact` or `clear --secrets-only` would be natural extensions; today anything after "clear" is ignored and it always does the full nuke. No `--json` consistency (clear emits JSON, but the contract is ad-hoc).

4. **No `--json` support documented or special-cased for clipboard the way env has it**: Env explicitly ignores `--json` in dispatch because "RunEnvCheck always emits JSON". Clipboard dispatch just passes `tail` through; the subcommand parser treats unknown as help text. A `blastradius clipboard --json check` would currently fall to the default case and print the usage string (not JSON).

5. **"status" vs "check" are synonyms only in the first arg; mixed usage is confusing**: `clipboard status --json` works because "status" triggers the check path. But the help text and command listing are inconsistent with "env" naming.

6. **Daemon-not-running still "succeeds" the read side-effect**: `pbpaste` always runs before the socket dial in the check path. On "daemon not running" you have still performed the clipboard read (and materialized its content) but receive only `{"status":"unknown"...}`. For the "safe check before I burn the paste" use case, the read happened without the benefit of the registry answer. (Same failure mode #7 in P4 eval.)

7. **Test simulation of pbpaste via `sh -c` in most happy paths**: The direct-exec invariant is asserted for the *tool names*, but realistic multi-line "clipboard" content in tests is produced by spawning a shell. This mirrors the env test situation. Not a prod bug, but a coverage divergence.

8. **No bounds on candidate volume or early exit on first find**: Same as P4 #8. A giant clipboard blob with hundreds of high-entropy tokens will produce that many CHECK_HASH exchanges. For a "just tell me if any secret is present" use case, we could short-circuit after the first known:true, but we don't (we count all for the `secrets_found` number, which is arguably useful).

9. **Clear uses `.Run()` with no error inspection or output**: `execCommand("pbcopy").Run()` — if pbcopy fails (permissions, no pboard server, etc.), the error is silently ignored and we still print the success JSON. Inconsistent with pbpaste error handling in the check path.

10. **No integration with P3's redaction policy or placeholder config**: Even if we wanted to implement redact-today for clipboard, there is no reuse. We'd have to duplicate the "for each confirmed secret value, strings.ReplaceAll(placeholder)" or the more sophisticated "fetch full known map once then scan" approach that scrub uses. (Scrub fetches the full set of hashes once in the handler; hygiene CLIs do per-value CHECK because they are the ones who extracted the candidates from untrusted surface content.)

---

## Structural / Architectural Problems

1. **Dead / aspirational config surface (echo of P4)**: `ClearSeconds` is fully implemented in the type + defaults + example + idiomatic doc + CURRENT_STATE caveat, but is completely unused dead code. This is the most glaring "letter vs implementation" mismatch for the *proactive* part of the telos. Worse, the declared semantics ("seconds after which a detected secret in the clipboard should be cleared") are now under active philosophical challenge: blind periodic clearing (regardless of content or user action) may be the wrong mental model entirely.

2. **P5 (and P4) are second-class citizens in the daemon/observability model**: No handler, no state in DaemonContext, no contribution to STATUS JSON or human status, no last-run / last-count / last-action. P2 and P1 have rich summaries and rescan; P3 has explicit results tied to the scrub command. Clipboard hygiene events are fire-and-forget from CLI processes. This makes "systematic evaluation of live clipboard exposure over time" impossible for users/admins and prevents future features (e.g. "alert if clipboard has had a secret in the last N minutes").
   - **The reactive alert / monitor proposal directly forces us to fix this.** A background watcher that needs to report "just detected secrets on change" *must* maintain and expose live state. Implementing the monitor + alerts will automatically give us `pillar5.clipboard.dirty`, `secrets_found`, `last_change`, etc. in status, and makes the whole pillar feel alive and integrated. This is a feature, not a bug, of the idea.

3. **The "auto" story for P5 lives in a uniquely gray space** (the core of the requested discussion):
   - Password managers implement auto-clear because *they* performed the copy of a secret *from a controlled vault item*. They have provenance and intent signal ("user asked to copy *this* secret").
   - General dev clipboard usage has no such signal. A secret appearing on the clipboard could be 100% intentional short-term use, 100% accidental, or "intentional but I will regret it in 5 minutes."
   - Therefore we *cannot* safely "clear immediately on detection."
   - A naive "every 30 seconds, clear the clipboard if it happens to have a secret right then" (or "start a 30s timer on every sighting") risks:
     - Destroying a secret the user just copied on purpose and is about to paste (or is in the middle of a multi-field form).
     - Nuking non-secret content that the user values.
     - Surprise for users who treat the clipboard as a reliable short-term holder.
   - The implementation model (CLI vs daemon) also matters: a timer started from a one-shot `blastradius clipboard check` dies when the process exits unless it daemonizes itself (ugly). A true background watcher belongs in the daemon (or a separate agent), which then must itself perform pbpaste + detection + CHECK_HASH (or a new internal primitive).

4. **No shared "surface hygiene primitive" abstraction**: Env and clipboard both do "materialize surface → ExtractCandidates → batch registry check → count + log". The socket part is duplicated; the surface-reading part is bespoke. Future surfaces (e.g. a "selection" on macOS, or editor buffers, or "last command output") would re-duplicate again. The P4 eval already flagged this.

5. **Detection / registration contract mismatch (cross-pillar architectural debt)**: Same as P4 #5. Not P5-specific, but P5 inherits the silent-miss surface for any P1-registered secret that fails the hygiene-side plausible gate.

6. **Clear and check have different "philosophies" with no unifying story**: Check is "tell me about secrets" (good). Clear is "destroy everything" (blunt instrument, never consults the registry or detector). There is no "scrub" or "redact" or "safe clear" that says "make the clipboard not contain any *known secrets* while preserving the rest." This is the exact gap the user highlighted: "It redacts the secrets via the pillar three logic."

7. **Logging init on every hygiene run (and global logger concerns)**: Same as P4 #7. CLI hygiene paths should not need to (re)initialize the daemon-oriented logger on every invocation.

8. **Pillar 5 never participates in exclusive-op or other daemon guards** (unlike P3). Not currently relevant because all mutating work (clear) is client-side, but if we ever move clear/scrub into a daemon handler for coordination, this would matter.

9. **macOS-only hard gate with no abstraction for future clipboards**: pbpaste/pbcopy are called by name with no platform shims, no "clipboard provider" interface, no graceful degradation on other OSes beyond the error message. Acceptable for v1 focus, but the primitive model should be designed so that adding Wayland/X11 `wl-paste` / `xclip`, or Windows `GetClipboardData`, is a localized addition rather than a rewrite.

---

## Other / Minor

- Help text and command summary are terse compared to env ("Pillar 5 clipboard status / clear (macOS)" vs the primitive language used for env).
- No dedicated end-to-end test that starts a real daemon + plants a secret via P1 + exercises real `blastradius clipboard check` and sees `known:true` + `secrets_found` (coverage is via overrides and pipes).
- Bitwarden-sourced secrets (P1) participate in clipboard checks by accident (same hashes) but there is no specific test or doc call-out.
- `blastradius check-hash <hex>` exists as a low-level escape hatch (used in some clipboard tests via override); the batch path in clipboard bypasses it.
- The "clear" action has no counterpart in the zsh wrappers beyond the thin passthrough (no `blastradius_clipboard_clear` convenience that also updates HUD or similar).
- Stale or aspirational language in places: some comments/docs still talk about "the timer" as if the shape is settled.

---

## First-Principles Design Space & Ideal User Stories (Not Derived from Current 30s Declaration)

The user request explicitly asked to "start from first principles, write some good stories about this and then ideal stories not stories from what exists presently" and to discuss the gray space between password-manager clipboard hygiene and dev CLI tooling. This section attempts exactly that.

**Guiding principles (proposed)**:
- We cannot know user *intent* when a secret appears on the clipboard. Assume mixed/unknowable.
- Therefore, we should never *immediately* destroy on detection (that would break legitimate one-shot intentional copies).
- **Fast feedback on the copy *event itself* is extremely high-leverage.** The watcher doesn't (only) have to auto-mutate the board; the highest-value thing it can do is tell the human "the dangerous thing just happened" while their attention is still on the copy action. Awareness > silent automation when intent is ambiguous.
- Time + stability is a reasonable proxy for "forgotten / left behind." A grace period gives the user a chance to use what they just copied.
- *Redaction* (remove only the secret parts, keep the shape and non-secret content) is strictly preferable to full clear when the copied material has structure the user may still want.
- Full clear ("nuke the board") remains a useful blunt tool for "I want the clipboard *empty* right now, secrets or not."
- The *primitive* (explicit, user- or prompt-invoked "look at the clipboard surface right now and tell me / clean it") is the reliable core, just like P4. Auto/timer behavior is *wiring* on top of the primitive and should be optional, observable, and conservative.
- Any auto behavior must be *conditioned on secret presence* (never "clear every 30s no matter what").
- The system should expose *both* an immediate manual hygiene action *and* (if we build auto) a "detect + decay after X while secret present" path.
- Observability and user education matter: when the system acts on your clipboard in the background, you should be able to see that it happened. The live "is the clipboard currently dirty?" state should be first-class in `status`.

**Ideal user stories (first principles)**:

> **Targeted scope:** Only the 5 stories below are in active scope right now. See the dedicated quick list [`docs/pillars/pillar5_user_stories.md`](pillar5_user_stories.md) for the ultra-short review version. The narratives here are the detailed versions with the specific refinements requested (fast first-secret alerting in story 4; independent redact + full-clear timeouts in story 5).

1. **"Is it safe to paste from the clipboard right now?" (visibility primitive)**
   - Developer has just run a tool or selected text and is about to paste into Slack, an AI prompt, a PR description, or another terminal.
   - They run `blastradius clipboard check` (or just `blastradius clipboard`).
   - Output: clean JSON or human "known secrets: 0" / "2 known secrets present in clipboard".
   - No values are shown. The act of checking itself is logged (to daemon log) with the count.
   - This is the direct analog of `blastradius env` before a risky `printenv`.

2. **"Get the secrets out of what I just copied, but keep the rest" (redact/scrub primitive)**
   - Developer accidentally cmd-c'ed a whole .env block, or a curl command with an Authorization header, or a JSON config containing a key, because they wanted the surrounding context.
   - They run `blastradius clipboard scrub` (or `redact`).
   - The tool: pbpastes, finds the known secret *values* that are present, replaces each literal occurrence with the configured placeholder (or a P3-derived one), pbcopies the redacted blob back.
   - Reports: `{"status":"ok","action":"redacted","secrets_redacted":1,"placeholder":"[REDACTED]"}`.
   - The clipboard now contains the useful structure with the dangerous parts gone. User can still paste the "skeleton" safely.
   - This reuses (or generalizes) the P3 redaction policy.

3. **"Nuke the entire clipboard right now" (blunt clear primitive)**
   - Developer wants the pasteboard *empty* (e.g., after handling sensitive material, or before walking away from the machine).
   - `blastradius clipboard clear` (or `clear --all` / `nuke`).
   - Unconditionally runs pbcopy with empty input. Reports success.
   - This remains available; it is *not* the default "hygiene" action.

4. **"The moment I copy anything, the system instantly tells me if the clipboard just became dangerous." (event-driven reactive alert)**
   - Any copy action from *any* source on the machine mutates the pasteboard.
   - The daemon runs a lightweight background monitor (polls pbpaste on short interval).
   - On detected change: run the Pillar 5 scan (pbpaste → ExtractCandidates → direct registry lookup inside the daemon).
   - **Fast alerting requirement (critical for UX):** Alert as soon as the *first* known secret is confirmed during the CHECKs. Do *not* wait for the full scan of a giant clipboard blob that happens to contain 10 secrets. The alert ("Secret(s) detected on clipboard") fires immediately for low latency. The exact count (`secrets_found: 10`) is still computed and surfaced later in logs + `status` + explicit `clipboard check`.
   - User who intentionally copied sees the alert and can ignore it. User who did it accidentally gets the signal while the copy action is still fresh in memory and can immediately `scrub` or overwrite.
   - This directly solves "we cannot know intent, therefore cannot clear immediately": we inform at the exact moment instead of guessing.

5. **"I copied something with a secret; protect me from my future self after a grace period" (two-tier auto with independent timeouts)**
   - When a secret is detected and the clipboard content remains stable:
     - After `redact_timeout_seconds` (default 30): auto-redact using P3 logic (replace only the secret values with placeholder, keep everything else the user copied).
     - After `full_clear_timeout_seconds` (default 60): full clear (nuke) the board.
   - Both timeouts are independently user-configurable under `pillar5`.
   - Intentional use window example: You copy a secret on purpose because you want to paste the value to an AI prompt (or a form). You don't want to manually go through redacting the clipboard afterwards. You paste the secret within the first ~30s window. The system will auto-redact the secret out of your clipboard for you after the redact timeout. If you ignore it longer the full clear happens at the longer timeout. If during use you want the secret to persist longer than the redact window, you have the full_clear window before total loss. Overwriting the clipboard at any time resets the timers for the new content.
   - This is the "grace period auto" safety net that sits on top of the reactive alert (story 4). The alert gives you immediate awareness; the two-tier timers give predictable cleanup without you having to remember to run a command.

**Open design questions for discussion (exactly as the user framed)**:
- **On the reactive alert idea**: Should the daemon's monitor fire an alert (notification + optional sound) *on every copy that results in known secrets being present*, or only on clean→dirty transitions, or with a cooldown to avoid fatigue? Should it be on by default when the daemon is running?
- Toolbar (persistent menu bar state + actions) vs. transient Notification Center popups vs. just audible + log + rich `status`? Can we start with notifications + sound (low implementation cost) and add a tray companion later?
- Can/should the notification be actionable (e.g. "Scrub" button that triggers the scrub primitive)?
- Should the monitor also produce a "clipboard is now clean" notice when a dirty board gets overwritten with clean content?
- Should the default auto behavior (if built) be *off*, and the primitives (`check`, `scrub`) + the reactive alerts be the always-on things? (Favors explicitness + awareness and "dev CLI tool" feel.)
- Or should a conservative "detect + redact after N seconds of stability" be on-by-default with loud logging and status visibility? (Favors "set and forget" protection like a PM.)
- What should `clear_seconds` actually mean once implemented? "Grace period from first sighting until auto-redact, reset on content change"?
- Should auto ever do *full clear*, or only redaction? (User's intuition: "I don't even think we should be clearing it all.")
- Should there be a `pillar5.mode: redact|clear` (mirroring P3) for the auto action?
- How do we surface auto actions so the user isn't surprised when their clipboard "magically" loses the secret they copied 40s ago?
- Should the watch/polling live in the daemon (requires daemon to do pbpaste + detection + CHECKs internally), or should we have a separate long-lived `blastradius clipboard watch` process the user can launch (or that `start` launches)?
- Is there a "clear after next paste" mode that is less time-based and more use-based? (Harder to implement reliably without hooking paste events.)
- Naming: `scrub`, `redact`, `clean`, `sanitize`, `purge-secrets` for the redacting action? For the monitor feature itself: `monitor`, `watch`, `alerts`, `reactive`?

---

## Recommendations (Prioritized)

1. **(Capture complete for monitor/alerts per plan)** The background clipboard monitor + reactive alert (fast on *first* secret confirmation) + two-tier auto (redact at redact_timeout, full clear at full_clear_timeout, independent user-configurable) has been implemented in daemon (with seams added for testability). This addresses the core of stories 4+5 + user's refinements. Remaining polish (dupe batch helper, more coverage, non-mac log, update all stale eval language) tracked in the approved capture plan.

2. **Decide and document the auto story from first principles before implementing any timer (or at least before making it do destructive things)**. Use the stories (especially the new reactive alert story) to define the relationship between "tell the human instantly" and "auto-clean after grace if they ignore it." Update docs after the decision.

3. **(Done) Add a redaction / scrub primitive for the clipboard (P3 reuse for placeholder)**. `blastradius clipboard scrub` (or `redact`) ... placeholder now configurable via new `pillar5.redact_placeholder` (falls back to pillar3 or default; piped through to both manual and auto redaction). See config and stories for details.

4. **Reframe the P5 CLI surface to match Pillar 4's "primitive" language and contract**. Make `blastradius clipboard` (default) or `blastradius clipboard check` the pure-observation hygiene function. Make `scrub` / `redact` the mutating safe-clean function. Keep or rename `clear` for the blunt nuke. Update help, docs, and the `RunClipboard` godoc. Consider accepting `--json` uniformly.

5. **Extract the shared batch CHECK + AUTH + reader logic** into a small internal helper (e.g. `internal/cli/hygiene.go` or `batchCheckHashes`). Both env and clipboard (and any future surface hygiene) should use it. This was recommendation #3 from the P4 evaluation; doing it now prevents further drift.

6. **Give P5 (and P4) a seat at the observability table** (this is now partially satisfied by the monitor work above). The monitor will naturally keep live `pillar5.clipboard` state. The explicit check/scrub paths should also report events so the full picture (manual + reactive) is visible in status.

6. **Fix the P1 registration vs detector gate mismatch** (or document the limitation loudly). This is the highest-severity leak that affects P5 (and P2/P3/P4). Either gate P1 values with the same plausible filter at registration time, or have hygiene paths do a "known lookup" that is more permissive for registry members. Until fixed, P5 can claim protection for secrets that it will never actually catch on the clipboard.

7. **Make the clear path inspect + log + condition**. Even the blunt clear should at least pbpaste first (or use a shared "get current clipboard + cands" helper), run detection, count how many *would have been* known, log "clear requested; N known secrets were present (or 0)", then do the pbcopy. This gives an audit trail.

8. **Add timeouts / output limits / early exit for the inspected surface** (clipboard read). A 10 MiB clipboard blob should not cause unbounded work or memory in the hygiene path.

9. **Add a small dedicated end-to-end test** (real daemon + real registry population from a P1 .env + real `blastradius clipboard check` asserting `known:true` and count). Mirror what is missing for env.

10. **Make logging init for CLI hygiene paths idempotent or a no-op when already initialized**, or ensure the test reset always forces a per-test temp log for the cli `getDaemonLogPathFn` path as well.

11. **(Later) Consider a platform clipboard abstraction** so that adding non-macOS support is a matter of implementing a small interface rather than forking the RunClipboard logic.

12. **Update all stale language** once the auto story is settled (remove "the timer is declared" hedging if we implement, or excise the field if we decide the auto model doesn't belong in P5 at all).

---

## Summary Verdict

**Meets the mechanical core for explicit manual use + upholds the direct-exec invariant.** The `check` path is a correct, detector-powered, hash-only observation of the live macOS clipboard and pairs naturally with the P4 primitive model. The `clear` path provides an immediate (if blunt) mutating tool.

**Does not meet the full telos** (automatic limiting / `clear_seconds` behavior is absent; redaction path is absent; the declared "clear after time" semantics are now recognized as potentially the wrong shape for the gray space this pillar occupies).

**Has leaks** (primarily the P1-vs-detector gate mismatch allowing registered secrets to go undetected when they appear on the clipboard; also full materialization of clipboard content, undercounting on partial CHECK failures, and zero post-clear observability).

**Has bugs and failure modes** (duplication with P4, loose JSON parsing, clear ignores its own context, no `--json` uniformity, daemon-not-running still causes the read side-effect, pbcopy errors swallowed, no size limits).

**Has structural/architectural problems** (dead config surface, second-class status/observability, the auto story is uniquely philosophically underspecified for a general dev clipboard vs controlled PM copy, no redaction reuse from P3, no shared hygiene primitive helper, macOS hard gate).

Pillar 5's *current* implemented surface (the check/clear primitives) is in good shape and was improved alongside the Pillar 4 work. The real work — and the real conversation — is defining what "Clipboard Hygiene" means in the dev-tool gray space: how much auto is appropriate, whether redaction is the primary limiting action, how to make the primitives feel like reliable "function calls" the rest of the system (and the user) can compose with, and how to give the pillar memory and visibility so it stops being a fire-and-forget afterthought.

This evaluation was performed via exhaustive source review + test runs in the blast-radius workspace. The `docs/pillars/pillar5_evaluation.md` file itself was created as the durable artifact of the review; no production code changes were made during the audit pass.

---

*Next step recommendation: treat this document as the input to a focused design conversation (exactly as the user requested). Write ideal stories, pick a coherent auto model (or decide to keep auto out of scope for v1 P5), then implement the primitives + wiring in a way that matches the decided heart, not the old 30s declaration.*
