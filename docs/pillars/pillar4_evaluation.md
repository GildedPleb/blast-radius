# Pillar 4 Evaluation — Runtime Environment Hygiene

**Date:** 2026 (systematic review)
**Scope:** Full implementation audit against the telos in `docs/pillars/idiomatic_pillars.md`, cross-referenced with `CURRENT_STATE.md`, `config.example.yaml`, code, tests, and related pillars (esp. P5 clipboard which shares patterns).
**Method:** Static code review (all call sites, data flows), behavioral tracing (exec paths, auth, candidate extraction), comparison of P1 registration vs hygiene detection, test execution (`go test ./internal/cli -run 'Env'` + full `./...`), doc/consistency checks, failure mode enumeration.

> **Note:** This document captures the state *before* follow-up fixes for several items it identified (test coverage for error+count path, terminology consistency, I/O logging in CHECK loops, dispatch arg handling, etc.). See the commit that introduced the "fix the bugs and nits" changes for the resolutions. The high-level gaps and recommendations remain relevant for future work.

---

## Telos (from idiomatic_pillars.md)

**Pillar 4 — Runtime Environment Hygiene**
- **Purpose**: Detecting secrets that are currently live in process environments.
- Periodically (or on prompt) runs user-defined commands (most commonly `printenv`) and scans their output for known secrets.
- Tells you, *right now*, whether dangerous material is sitting in your shell or tool environments.
- **Hard security invariant**: Commands under `pillar4.commands` are *always* executed via direct `exec` (never through a shell). Eliminates shell metacharacter injection / ACE from config. Use wrapper scripts for pipes/complexity.
- **Core question**: "What secrets are currently readable by running `printenv` or similar introspection commands?"
- "This is the 'can I safely run printenv right now without burning anything?' check."

Summary table positions it as: "Detect live secrets in current environments" / "'Is it in my shell right now?'"

---

## Implementation Overview

- **Config**: `internal/config/config.go` — `Pillar4Config { Commands []RuntimeCommand }`; `RuntimeCommand { Name, Cmd string, AutoOnPrompt bool }`.
  - Default: one `{"default-env", "printenv", AutoOnPrompt: true}`.
  - Hard-coded comment on direct-exec invariant.
- **CLI entry**: `internal/cli/env.go:RunEnvCheck` (dispatched from `cli.go` for `blastradius env [name]`).
  - Finds named command, `strings.Fields(Cmd)`, `execCommand(parts[0], parts[1:]...).CombinedOutput()`.
  - On success: `detection.NewDetector().ExtractCandidates(output)`, per-candidate `registry.HashValue` + manual `CHECK_HASH <hex>` over Unix socket (with optional AUTH).
  - Reports `{"status":"ok","command":"...","secrets_found":N}` (N = distinct known values).
- **Daemon side**: Only `CHECK_HASH` handler + `IsKnownHashHex` (thin pass to `registry.IsKnownHashHex`). Multi-command support on one conn explicitly for env (and clipboard).
- **Detection**: Shared `internal/detection/detector.go:ExtractCandidates` (line-aware = parsing, high-ent regex seeds, quote stripping, noise/entropy gates, structured JSON, broad word fallback). Used by P2/P3/P4/P5.
- **P5 sibling**: `clipboard.go` has near-identical manual multi-CHECK + AUTH socket code.
- **No daemon tracking**: Pure client-side after registry query. No Pillar 4 section in STATUS, no last-run / last-count.
- **Zsh**: Thin wrapper `blastradius_env() { _blastradius env "$@"; }`; `prompt_info` only does `status --json` (no auto env).
- **Docs**: `config.example.yaml` loud on invariant + wrapper advice + `auto_on_prompt`; `idiomatic_pillars.md` and `CURRENT_STATE.md` mark "✅ Complete".

Tests: `internal/cli/env_test.go` (happy path with net.Pipe + realistic KEY=val, direct-exec invariant test, no-cands, auth-fail, basic branches). Full suite `./...` passes.

---

## Does It Meet the Letter and Heart of the Purpose (Telos)?

**Partial — on-demand core works, but aspirational framing is not implemented.**

- **Positive (letter of core job)**:
  - Running `blastradius env` (or named) *does* exec the configured command directly, extract plausible values via unified detector, hash, CHECK against live registry, and report count of matches.
  - Hard invariant upheld in prod path + enforced by dedicated test (`TestRunEnvCheck_DirectExec`).
  - Output of command never emitted to user (only count); values live only briefly in []byte inside CLI proc. "Burn" surface is avoided for the *check itself*.
  - Uses post-2026 unified detection (addresses prior TODO about naive whole-output hashing).
  - Safe degradation: unknown cmd / exec fail / no-daemon reported as JSON error (no crash in normal paths).

- **Gaps vs heart / stated purpose**:
  - **"Periodically (or on prompt)" is pure vaporware**. `AutoOnPrompt` field exists, is defaulted true, documented/recommended in example + idiomatic doc, but **never read anywhere in the codebase**. Zero timers, no prompt-hook integration, no zsh PROMPT hook that would invoke env cmds, no daemon background scheduling. The "on prompt" / periodic behavior described in the telos and docs does not exist.
  - Current UX is purely manual + reactive (`blastradius env`). You must remember to run the check *before* doing a risky `printenv` or equivalent. This falls short of "tells you, right now" in a proactive hygiene sense.
  - No observability: `status` (human or --json) has zero Pillar 4 data (no last hygiene run, per-command counts, AutoOnPrompt status). Contrast with P1 (collector_results, scan_state) and P2 (crumbs summary).
  - Zsh HUD is visibility-only for P1; no auto hygiene.

**Verdict on telos**: Meets the mechanical "run cmd + hash check output" for explicit invocation. Does *not* meet the full described purpose or "heart" (live, low-friction, prompt/periodic awareness of runtime exposure). The implementation is closer to a "manual runtime auditor" than the described hygiene pillar.

---

## Leaks (Secret Material Exposure or Missed Detections)

1. **Structural false-negative leak (most serious)**: P1 registration (discovery/scanner.go `collectHashesFromFile`) accepts *any* non-empty, non-ignored-key value from .env* (no minlen, no entropy gate). Hygiene pillars (including P4) go through `Detector.ExtractCandidates` → `isPlausibleSecret` (len >=8, entropy >=4.0, !isCommonNoise).
   - `isCommonNoise` drops strings containing "password"/"secret"/"changeme"/... when len<20, or all-repeated chars.
   - Result: Weak, short, low-entropy, or "noisy-word" secrets deliberately stored in legitimate Pillar 1 sources **will be in the registry but will never be extracted as candidates from printenv / history / clipboard / residue**, so never detected by P4 (or P3/P2-known-matches/P5).
   - Example vectors: short dev passwords, values containing "secret" or "token" substrings under 20 chars, dictionary-ish strings, etc.
   - This is a systemic mismatch between "ground truth" (P1) and all "where should not / live surfaces" detection. Hygiene can silently fail to report live exposure of exactly the secrets it claims to protect.

2. **Nonzero-exit commands leak secrets in output**: `output, runErr := ...CombinedOutput(); if runErr != nil { report error; return }` — output (which may contain secrets on stderr/stdout for failing kubectl, custom wrappers, etc.) is discarded without scanning. Only success-path output is candidate-extracted.

3. **Memory + process exposure during check**: Even on "daemon not running" or error paths, the full command output (entire `printenv`, potentially huge secret-laden kubectl yamls, etc.) is materialized in the CLI process RAM before any check or early return. If the process is coredumped, swapped, or inspected mid-run, material is exposed. (Unavoidable for the introspection model, but worth noting; no streaming/limited/cancel.)

4. **Auth / conn failure undercounting**: If AUTH fails or mid-loop socket dies, subsequent CHECKs silently fail (errors ignored), `found` undercounts, but final JSON is always `status:ok` with the (wrong) number. User may believe "0 found" when checks were aborted.

5. **No redaction or limiting of the hygiene command's own output in logs**: Logging only command *name* + final count. However, if a user-defined cmd under pillar4 emits to its own stderr that gets Combined, and later somehow... (current paths don't leak via logging).

6. **Test logs can pollute real daemon.log**: RunEnvCheck (and thus tests) calls `logging.Init(getDaemonLogPathFn())` which targets the *real* `~/.local/state/.../daemon.log` (reset only partially overrides via daemon pkg hook, not cli's get fn). Test runs append to live user logs.

---

## Errors, Bugs, and Failure Modes

1. **Reader creation bug in env vs clipboard**: env.go creates `reader := bufio.NewReader(conn)` *inside* the per-candidate loop (and discards prior). Clipboard correctly creates once before loop. Risk of lost buffered data, extra syscalls, or inconsistent behavior on partial reads/EOF. Duplicate code amplifies.

2. **~ not expanded for commands**: `parts := strings.Fields(cmd.Cmd); execCommand(parts[0], ...)` — no `util.ExpandPath`. Docs say "absolute (or PATH-resolvable)"; comments in example use `/Users/...`. A user putting `cmd: "~/bin/scan-env"` (natural) will get "command failed: exec: ... no such file". Inconsistent with P1/P2/P3 path handling everywhere else.

3. **No timeout on user commands**: `CombinedOutput()` blocks forever if the configured cmd hangs (interactive tool, network wait, bad wrapper, etc.). `blastradius env` can be DoS'd via config. No context, deadline, or size limit on output.

4. **Naive cmd parsing + poor error UX**: `strings.Fields` has no quoting/escaping support. A cmd with spaces in args will produce wrong argv (literals passed). On exec failure, user gets raw `{"status":"error","message":"command failed: <exec err>"}` — no hint about the direct-exec rule or wrapper recommendation.

5. **Always-"ok" final status + ignored I/O**: Post-exec, the CHECK loop + final printf always succeed with "ok" + count (even 0). Write errors on conn, read errors, auth rejections after the fact, etc. are swallowed. The only way to get error JSON is pre-loop (unknown cmd, empty, exec fail, initial dial fail).

6. **Test fragility / non-hermetic paths**:
   - `TestRunEnvCheck` (the branch-coverage one) in isolation causes `go test -run '^TestRunEnvCheck$'` to report FAIL (despite no `t.Error` and recover around the deliberate panic from nil cfg after error-load + osExit-noop). Full suite passes due to ordering + resets from other tests. The recover + mid-test `resetTestOverrides(t)` + silenceOutput interaction is brittle.
   - Logging init side effects real FS even under reset.
   - Happy-path test bypasses real AUTH (no .auth file in temp socket setup) and uses fake pipe server that doesn't enforce daemon auth rules.

7. **Daemon-not-running still executes the side-effect**: `blastradius env` always runs the configured command *before* the socket dial. On "daemon not running" you have still performed the full introspection (and captured its output) but receive only an error (no count). For the "safe check before I burn" use case, this means the check action itself happened without benefit.

8. **No bounds on candidate volume**: A huge printenv or secret dump cmd can produce thousands of candidates; each does a socket write + read. No truncation, batching, or early abort.

9. **Loose response parsing**: `strings.Contains(resp, `"known":true`)` — works for current handler but fragile if JSON formatting or extra fields change (no proper unmarshal).

10. **Pillar 4 never participates in exclusive-op or other daemon guards** (unlike P3 scrub).

---

## Structural / Architectural Problems

1. **Dead / aspirational config surface**: `AutoOnPrompt` is fully implemented in the type + defaults + docs + example, but is unused dead code. This is the most glaring "letter vs implementation" mismatch.

2. **Code duplication with P5**: env.go and clipboard.go duplicate ~30 lines of socket dial + optional AUTH (no response read) + per-cand CHECK_HASH + loose parse. Env's version is the weaker one. A shared helper (e.g. `batchCheckHashes(conn, cands) int`) would be obvious, but absent. Violates DRY; risks one pillar getting auth changes the other doesn't.

3. **Ad-hoc protocol in CLI layer**: The multi-CHECK optimization lives only in two hygiene CLIs. `sendDaemonCommand` (the canonical path) does single command + full AUTH handshake with error checking. Inconsistency in auth "best effort" treatment between paths.

4. **Pillar 4 is second-class citizen in the daemon/observability model**:
   - No handler, no state in DaemonContext, no contribution to STATUS JSON or human status.
   - P2 and P1 have summaries and rescan; P3 has scrub results; P4/P5 are fire-and-forget client-side.
   - Makes "systematic evaluation of live runtime hygiene" harder for users/admins.

5. **Detection / registration contract mismatch** (cross-pillar architectural debt): The "plausible secret" filter lives only on the hygiene side. P1 is the authority for "known", but detection can drop values that P1 accepted. This affects P2-known, P3, P4, P5 symmetrically. Not a P4-only bug, but P4 inherits it.

6. **No wrapper/expansion helper for RuntimeCommand.Cmd**: Other pillars centralized path expansion (util.ExpandPath) + glob (MatchesGlobPattern). P4 cmd handling is bespoke split + raw exec.

7. **Logging init on every hygiene run**: Every `env` or `clipboard` call does `_ = logging.Init(...)`. Logging is daemon-oriented; CLI hygiene shouldn't need to (re)initialize the global logger each time.

8. **No size / sensitivity limits**: User can configure a cmd that emits megabytes of data (full k8s secret dumps, etc.). All materialized + candidate-extracted.

9. **Test surface vs prod divergence**: Many env tests override execCommand to `sh -c 'printf ...'` to produce realistic output. The direct-exec *test* correctly asserts argv, but the bulk of coverage for "realistic printenv-style" paths goes through shell in test only.

---

## Other / Minor

- README.md still says "Pillar 5 (`env`)" in one place (copy-paste debt from the renumbering).
- No dedicated integration test that starts a real daemon + plants a secret via P1 + runs real `blastradius env` end-to-end (all coverage is mocked at config/exec/dial layer).
- Bitwarden source (P1) can contribute hashes; they will be checked by P4 if they appear in runtime envs of tools — works by accident but untested specifically.
- `blastradius check-hash <hex>` is a separate low-level command (used by clipboard in some tests); env bypasses it for batching.

---

## Recommendations (Prioritized)

1. **Implement or excise the periodic/prompt story**: Either wire `AutoOnPrompt` (e.g. via zsh prompt hook that invokes `env` for marked commands, or a lightweight daemon timer) or remove the field + update all docs/telos so the stated purpose matches reality. Currently the biggest "heart" gap.
2. **Fix the plausible filter vs P1 contract**: Either (a) make P1 also gate values with the same detector logic at registration time (so registry only ever contains plausible), or (b) have hygiene paths do a "known lookup" pass that bypasses the full plausible gate for candidates that might match (risk of noise), or (c) document loudly that only high-entropy secrets are protected by hygiene pillars.
3. **Extract shared batch CHECK helper** and make AUTH + multi-command robust (proper err checking, single reader, read AUTH responses if daemon ever starts sending them).
4. **Add ~ expansion + better cmd validation** for RuntimeCommand (or at minimum clear error + docs).
5. **Add timeouts + output limits** to hygiene command execs.
6. **Surface Pillar 4 in status** (last hygiene timestamp + per-command last count or "clean/dirty").
7. **Scan output even on nonzero exit** (or at least have an option; many introspection cmds are "best effort").
8. **Harden the first TestRunEnvCheck** (or delete the weak branch-coverage test if the others cover).
9. **Make logging init idempotent or skip for CLI hygiene paths** (or ensure reset always forces a temp log for cli getDaemonLogPathFn too).
10. **Add an end-to-end test** using the real daemon + registry population + `env` invocation.

---

## Summary Verdict

**Meets the mechanical core for explicit manual use + upholds the direct-exec invariant.**  
**Does not meet the full telos** (periodic/prompt behavior absent; "live hygiene" is opt-in manual only).  
**Has leaks** (primarily the P1-vs-detector gate mismatch allowing registered secrets to go undetected in runtime surfaces; also nonzero-exit path).  
**Has bugs and failure modes** (hangs, undercounting, ~ expansion, reader-per-iter, always-ok status, test fragility).  
**Has structural/architectural problems** (dead config, duplication with P5, second-class observability, ad-hoc protocol, cross-pillar contract inconsistency).

Pillar 4 is one of the simpler pillars and the direct-exec security story is solid, but it shows signs of being "finished to v1" without the full proactive framing or complete consistency with the rest of the five-pillar system. The unified detection work helped, but exposed (or inherited) the registration/detection impedance mismatch.

Further work on P4 should be gated on deciding the fate of `auto_on_prompt` and addressing the false-negative surface for secrets that P1 claims.

---

*This evaluation was performed via exhaustive source review + test runs in the blast-radius workspace. No changes were made to code during the audit.*
