# Implementation Plan: Pillar 2 — Illegitimate Secret Residue Hunter ("Crumbs")

**Date:** 2026 (plan phase)  
**Status:** Ready for implementation approval  
**Related docs:** [residue_hunter_scoped.md](residue_hunter_scoped.md), [idiomatic_pillars.md](idiomatic_pillars.md), [../CURRENT_STATE.md](../CURRENT_STATE.md)

---

## 1. Context & Why Now

Pillar 2 is the explicit **inversion of Pillar 1** (see idiomatic_pillars.md):

- Pillar 1: "secrets where they *should* be" (`.env*` files inside configured project roots → central `registry.Registry`).
- Pillar 2: "secrets where they *should not* be" — forgotten vault exports, bulk dumps, and high-entropy blobs left in high-risk user locations (Downloads, Documents, Desktop, etc.).

Current state (CURRENT_STATE.md): **Zero implementation**. Only the design document exists. All other pillars (1, 3, 4, 5) have CLI commands, daemon handlers, and status integration.

Completing Pillar 2 fulfills the "Five Pillars" vision and closes the largest remaining gap. The scoped design (no Full Disk Access, only high-likelihood "residue sinks" an attacker would already look in) keeps the security posture intact.

User feedback during planning clarified v1 boundaries (see decisions below).

---

## 2. Goals for v1 + Explicit Pillar 2 Completion Roadmap

**v1 goal (MVP — "Crumbs" high-confidence export hunter):**  
Ship the scoped vault-export + generic high-entropy detector limited to user-configured high-risk directories (`~/Downloads` etc.), on-demand only, `blastradius crumbs` + status summary. This is a valuable, low-risk, high-signal feature that stands on its own.

**However — per user review feedback:** The items listed as "non-goals for v1" below are **not optional polish**. They represent the original "residue sinks" vision and the honest assessment of realistic locations in the design document. **Pillar 2 is not considered fully operational until these stages are complete.**

### Pillar 2 Full Completion Stages (must be documented + tracked)

1. **Stage 1 (this plan — v1 "Crumbs")** — Vault export formats + generic high-entropy inside the narrow `target_dirs` surface. On-demand `crumbs` command. Status summary. (Current work.)
2. **Stage 2** — Add `hunt_residue: true` support *inside the same target_dirs*: editor swap/backup patterns (`*.swp`, `*.swo`, `*~`, `.#*`, `*_backup*`, crash dumps, etc.) + lower-entropy threshold for smaller residue blobs. Still advisory only.
3. **Stage 3** — Expand the scanning surface to the *realistic materialization locations* identified in the design doc (project directories + `/tmp` + `~/tmp` + `~/.cache` + `~/Library/Logs` + git working-tree/reflog/stash). This may require a second config section (e.g. `residue_hunter.materialization_roots` or reuse `project_roots` + well-known temp dirs) and/or a combined "residue + materialization" scan mode.
4. **Stage 4 (optional but powerful)** — Lightweight git accident detection (reflog + stash + uncommitted) tied to project roots, plus bounded recent-commit gitleaks-style checks (opt-in).
5. **Stage 5** — Background / event-driven scheduling or fsnotify reactivity for the hunter (user request during planning).
6. **Stage 6** — Zsh HUD surface + any final polish (auto-delete suggestions remain strictly advisory / never automatic).

**Documentation requirement:** Before implementation of Stage 1 begins, the plan + `residue_hunter_scoped.md` must clearly label the current work as "Stage 1 of 6" and list the full roadmap so future contributors know Pillar 2 has a defined "done" state.

This staged view respects the user's explicit desire that all the residue-finder concepts (swap files, temp, cache, git, etc.) be "very well documented" as required work, not hand-wavy future ideas.

---

## 3. Naming Decisions (Resolved via User Input)

- **CLI command:** `blastradius crumbs`  
  (Inspired by "you forgot to flush the toilet / left crumbs" analogy — short, memorable, unique in the tool, evokes "trail of forgotten secret material".)
- **Daemon protocol command:** `CRUMBS`
- **Handler:** `CrumbsHandler`
- **Package:** `internal/residue` (internal name can still reference "residue" for code clarity; user surface uses "crumbs").
- **Config section:** `residue_hunter` (kept for consistency with design doc; the "crumbs" name is user-facing only).

Status / JSON will use neutral keys like `residue_findings` or `crumbs` (recommend `residue` for internal keys to match design doc language).

---

## 4. Recommended Architecture (v1)

Follow existing thin layers + delegation pattern:

```
CLI (crumbs.go)
  → sendDaemonCommand("CRUMBS")
Daemon (unix socket)
  → handlers/crumbs.go (CrumbsHandler)
    → d.CrumbsFindings()  (via extended DaemonContext)
      → residue.Manager (owns last scan, performs walk + detection)
        → residue.Scanner / detectors (filename + format + entropy)
          → registry.Has(...) for known-secret matches
```

**New package:** `internal/residue/` — deliberately separate from `discovery/` because the scanning rules, output shape, and purpose are inverted (bad locations vs good locations).

**Reuse (high fidelity):**
- `discovery` ignore/skip logic (via exported helpers or small shared util — see steps).
- `registry.Registry` (read-only `Has`, `AllHashes` not required here).
- `daemon` + handler + CLI dispatch patterns (exact match to `duplicates`, `scrub-history`).
- `config.Load` + `DefaultConfig`.
- Privacy name helpers (similar to `computeDisplayName` / `ProjectDisplayName`).
- `expandPath` logic for `~`.

**New data flow (no new persistence):**
- Findings live only in the running daemon process (in-memory).
- On `CRUMBS` command: manager runs a fresh scan (or returns cached if very recent — optional simple debounce), returns serializable result.
- Never store full paths; only privacy-friendly location strings + metadata + count of known-secret hits + entropy hits.
- On daemon exit: findings disappear (correct for sensitive list).

---

## 5. Config Surface (v1) — Simplified per Review Feedback

**Critical decision (user review):** The `known_export_formats` list (and ability to selectively disable specific vault detectors) **must not exist**.

Rationale: These are dangerous artifacts that should *never* exist in cleartext in high-risk locations. The tool's job is "fuck you, don't do this." Users should not be able to turn off detection for Bitwarden, Dashlane, 1Password, or generic high-entropy dumps. We ship a fixed, complete set of detectors and always run all of them when the feature is enabled.

Revised minimal config surface:

```yaml
residue_hunter:
  enabled: false                 # default false (opt-in)
  target_dirs:
    - "~/Downloads"
    - "~/Documents"
    - "~/Desktop"
    # user additions allowed (e.g. "~/backups", mounted volumes when present)
  flag_suspicious_filenames: true   # filename patterns that strongly suggest secret dumps (always-on when enabled)
  # min_high_entropy_hits: 3        # (optional for v1; can be a hard-coded sensible default inside the detector)
  # max_file_size_mb: 10            # (recommended safety bound, hard-coded or simple config)
```

- Only `enabled` + `target_dirs` are truly required for v1.
- `ResidueHunterConfig` struct is tiny.
- All detectors (Bitwarden JSON/CSV, Dashlane, 1Password .1pif, generic high-entropy JSON/CSV/text) are **unconditionally included** when enabled. No user knob to subset them.
- Update `DefaultConfig()` and `Load()` accordingly.
- This also simplifies the detector code (no "which formats are active?" branching).

This keeps the spirit of the design doc while respecting the "never allow disabling core dangerous-artifact detection" principle.

---

## 6. Implementation Steps (Ordered, Minimal Diff)

### Phase 0 — Foundations (small refactors for reuse)

1. **~ expansion (KISS decision)**  
   Duplicate the tiny `expandPath` logic (from `discovery/manager.go:68`) inside `residue/manager.go` for v1. Creating a new `internal/util` package would be premature abstraction given the project's YAGNI philosophy. Later, if three+ places need it, extract. This keeps the PR surface smaller.

2. **Skip / ignore reuse (discovery package)**  
   `residue` will `import "github.com/GildedPleb/blast-radius/internal/discovery"` and directly use `discovery.NewIgnoreMatcher(root, cfg.IgnoreFiles)` plus the same `skipDirs` map construction pattern that `scanner.go` uses. No new exports needed for v1 — the logic is already simple and package-level. This achieves "using existing discovery patterns with skips" from the design doc with zero changes to discovery.

### Phase 1 — Core Residue Package

3. **New file: `internal/residue/types.go`**  
   - `ResidueFinding` struct (Location string, Basename string, LastMod time.Time, Format string, Confidence string, KnownMatches int, EntropyHits int, Size int64).
   - `ScanResult` { Findings []ResidueFinding, ScannedDirs int, FilesExamined int, Duration time.Duration, Timestamp time.Time, Errors []string }.
   - Constants for formats and confidence levels.

4. **New file: `internal/residue/detector.go`** (or `detectors.go`)
   - `FilenameHeuristic(name string, cfg ResidueHunterConfig) (isSuspicious bool, formatHint string)`
   - `ComputeEntropy(s string) float64` (Shannon entropy, simple charset or 0-8 bits/char impl — ~20 lines).
   - `ExtractHighEntropyStrings(data []byte, minLen int) int` (regex for base64/hex/long random + entropy filter).
   - `DetectBitwardenJSON(data []byte) (hits int, isExport bool)` — look for `"encrypted":false`, `"items"`, count high-entropy strings in password/login/notes/fields.
   - Similar lightweight detectors for CSV (column names + cell entropy), Dashlane, 1pif (if structure known; else treat as generic).
   - `ScanFile(path string, cfg ...) (finding *ResidueFinding, err error)` — size gate, read, try format detectors in priority order, fallback generic entropy, return nil if below thresholds.

5. **New file: `internal/residue/manager.go`**
   - `Manager` struct { cfg *config.Config, reg *registry.Registry, last *ScanResult, lastScan time.Time }
   - `NewManager(cfg, reg) *Manager`
   - `RunScan() *ScanResult` — expands target_dirs, walks each with `filepath.WalkDir` (or Walk), applies skip_dirs + ignore_matcher (per root), calls detector on promising files, checks `reg.Has(hash)` for any extracted candidate values, builds privacy-friendly Location via helper (e.g. `safeLocation(absPath)` → "Downloads/bitwarden_export_2024-03-12.json"), collects findings, records metadata.
   - Graceful error handling per directory (one bad dir never kills the whole scan).
   - `GetLastResult() *ScanResult` (for status summary without re-scan).
   - No goroutines/tickers here (on-demand only per user decision).

6. **New file: `internal/residue/safe_names.go`** (or inline)
   - `SafeLocation(absPath string) string` — analogous to discovery's `computeDisplayName`. For residue we can be slightly more specific (include basename) because the locations are user-controlled high-risk dirs: e.g. "Downloads/very-secret.json" or "~/Downloads/..." depending on taste. Never return full home prefix if it adds sensitivity.

### Phase 2 — Daemon & Handler Integration

7. **Update `internal/daemon/context.go`** and **`internal/daemon/handlers/handlers.go`** (both — they duplicate the interface)
   - Add:
     ```go
     CrumbsSummary() map[string]any   // lightweight for status (count, last_scan, top locations)
     RunCrumbsScan() *residue.ScanResult
     ```
   - Import `"github.com/GildedPleb/blast-radius/internal/residue"` in daemon package as needed.

8. **Update `internal/daemon/daemon.go`**
   - Add `residue *residue.Manager` field.
   - In `New()`: `res := residue.NewManager(cfg, reg); ...`
   - Implement the two new DaemonContext methods (delegate to manager; the summary method can synthesize a small map without exposing full types to handlers layer).
   - In `handleConnection` switch: `case "CRUMBS": handler = handlers.CrumbsHandler{}`
   - (Optional) On startup, if `cfg.ResidueHunter.Enabled`, you may eagerly run one scan and log "Pillar 2 initial crumbs scan complete: N findings" — but keep cheap.
- In `RunScan()` (and handler): if `!cfg.ResidueHunter.Enabled`, return a clean `{status:"disabled","message":"residue_hunter.enabled is false in config"}` (or empty findings). Never error.

9. **New file: `internal/daemon/handlers/crumbs.go`**
   - `type CrumbsHandler struct{}`
   - `Name() string { return "CRUMBS" }`
   - `Handle(args, d) (any, error)` — call `d.RunCrumbsScan()`, convert findings to serializable []map (location, format, known_matches, entropy_hits, last_mod), return `{status:"ok", findings:..., total: len, scanned:..., timestamp:...}`. On error, graceful message.

### Phase 3 — CLI Surface

10. **New file: `internal/cli/crumbs.go`**
    - `func RunCrumbs()`
    - Call `sendDaemonCommand("CRUMBS")`
    - Pretty-print: header "Blast Radius - Forgotten Secret Crumbs (Pillar 2)", count, per-finding lines with recommendation ("Review and securely delete or move to vault"), footer with total examined.
    - Handle daemon-not-running case exactly like duplicates/scrub-history.
    - Also support `--json` for machine consumers (consistent with status).

11. **Edit `internal/cli/cli.go`**
    - Add `case "crumbs": RunCrumbs()`

12. **Edit `internal/cli/help.go`**
    - Add under Commands: `  crumbs         Pillar 2: locate forgotten vault exports & high-entropy dumps in high-risk dirs`

13. **Edit `internal/cli/status.go`**
    - In human-readable path: after registry section, if daemon present, add a small "Pillar 2 (Crumbs)" line using the new `CrumbsSummary()` data (e.g. "Crumbs found: 2 (last scan: 3m ago)").
    - In JSON path: include the summary under `daemon.residue` or `daemon.crumbs` (lightweight — count + last_scan + sample locations only; full list stays behind dedicated command).
    - Update `daemonOrNotRunning` sentinel if needed (no change required).

### Phase 4 — Wiring, Config, Examples, Polish

14. **Edit `internal/config/config.go`**
    - Define `type ResidueHunterConfig struct { ... }` with all fields from §5.
    - Add `ResidueHunter ResidueHunterConfig `yaml:"residue_hunter,omitempty"`` to `Config`.
    - Update `DefaultConfig()` with disabled + sensible lists.
    - In `Load()`, after unmarshal, ensure sub-struct has defaults if partially populated (or do it in residue.Manager).

15. **Edit `config.example.yaml`**
    - Add a documented `residue_hunter:` block (can be commented out or present with `enabled: false` + explanation linking to pillars doc).

16. **Update tests (parallel with code)**
    - `internal/residue/*_test.go` (new): unit tests for entropy, filename heuristics, synthetic Bitwarden JSON/CSV detectors, SafeLocation.
    - `internal/daemon/handlers/crumbs_test.go`: using existing `fakeContext` pattern (add the new methods to the fake).
    - `internal/cli/crumbs_test.go` (pattern match existing command tests).
    - Update any config tests that assert exact struct shape.
    - Ensure existing test suite (`go test ./...`) still passes (no breakage to Pillar 1/3/4/5 paths).

17. **Update `internal/daemon/daemon_test.go`** (minimal — NewDaemon check can stay or add residue field assertion).

---

## 7. Key Technical Details & Guardrails

- **No plaintext ever**: Only hashes of candidate values extracted from suspect files are checked against registry. High-entropy counts are pure integers. Filenames/locations are metadata only.
- **Size & safety gates**: Hard cap on file size examined (recommend 10–20 MiB default). Skip binary-ish files (or at least don't treat as JSON/CSV if magic bytes suggest image/db).
- **Error model**: Per-file and per-dir errors are collected and reported in the result; scan never crashes the daemon.
- **Privacy display names**: Mirror the existing discipline — `SafeLocation` lives in one place. Prefer relative-to-home forms like `Downloads/export.json`.
- **Performance**: Walk is bounded by target_dirs count (usually 3–6). Detectors are cheap (name first, then bounded read + parse). Fine for on-demand.
- **Invariants upheld** (see CURRENT_STATE §7): all 8 existing + new implicit "Pillar 2 findings never persisted."
- **Backwards compat**: Adding the config section + new command + new status keys is additive. Old clients ignore unknown JSON keys.

---

## 8. Files Touched (Summary Table)

| File | Action | Notes |
|------|--------|-------|
| `internal/residue/types.go` | Create | Core structs |
| `internal/residue/detector.go` | Create | Heuristics + format parsers + entropy |
| `internal/residue/manager.go` | Create | Scan orchestration + last result |
| `internal/residue/safe_names.go` | Create | Privacy helper (or merge) |
| `internal/residue/*_test.go` | Create | Unit coverage |
| `internal/daemon/handlers/crumbs.go` | Create | Handler |
| `internal/daemon/handlers/crumbs_test.go` | Create | FakeContext wiring |
| `internal/cli/crumbs.go` | Create | Pretty + JSON output |
| `internal/cli/crumbs_test.go` | Create | CLI test |
| `internal/config/config.go` | Edit | ResidueHunterConfig + defaults |
| `config.example.yaml` | Edit | Documented example section |
| `internal/daemon/context.go` | Edit | Extend interface |
| `internal/daemon/handlers/handlers.go` | Edit | Extend duplicate interface (keep in sync) |
| `internal/daemon/daemon.go` | Edit | Manager field, methods, switch case |
| `internal/cli/cli.go` | Edit | Dispatch |
| `internal/cli/help.go` | Edit | Docs |
| `internal/cli/status.go` | Edit | Summary + JSON |
| `docs/CURRENT_STATE.md` | Edit | Mark Pillar 2 complete, update tables |
| (no `internal/util`) | — | ~ expansion duplicated inside residue for v1 (KISS) |

~17–20 changed/added files total (no new util package). Most are small and follow existing patterns.

---

## 9. Testing & Verification Strategy

**Unit:**
- Pure detector functions with table-driven tests (synthetic JSON/CSV blobs with known secrets + noise).
- Entropy scorer against known high/low strings.
- Filename heuristic matrix (bitwarden_export_2025.json → true, cat.jpg → false, etc.).

**Integration-style:**
- Handler tests via `fakeContext` (inject pre-populated registry + simulate findings).
- CLI tests using `mockSendDaemonCommand`.

**End-to-end manual (critical):**
1. `go build -o /tmp/br ./cmd/blastradius`
2. Create temp `~/tmp/br-test-downloads/` with 1–2 synthetic export files (realistic Bitwarden JSON containing 5+ fake passwords that will also be planted in a test .env).
3. Create minimal `~/.config/blastradius/config.yaml` with `residue_hunter.enabled: true` + `target_dirs` pointing at the test dir + one project_root containing the matching .env.
4. `/tmp/br start`
5. `/tmp/br crumbs` → expect: reports the export file, shows "known secret matches: 5", "entropy hits: X", recommendation.
6. `/tmp/br status --json` → contains `residue` or `crumbs` summary with count > 0.
7. `/tmp/br duplicates` still works, registry counts correct.
8. `strings /tmp/br | grep -i 'myfakepassword123'` → no hits (invariant).
9. Kill daemon, re-run `crumbs` → graceful "daemon not running".
10. Re-run with `enabled: false` in config → `crumbs` reports disabled cleanly (no crash, no scan performed).
11. `go test ./...` — all green, including new tests.

**Security spot-checks (in plan review or PR):**
- Full paths never appear in status JSON or crumbs output (only safe names).
- Large binary file in target dir is skipped, not read.
- Permission error on one target dir does not abort others.

---

## 10. Documentation Updates

- `docs/CURRENT_STATE.md`: Update "Pillar 2" row from "Zero work done" to "Implemented (v1 — crumbs command + detector + status summary)". Add to commands list. Update known limitations.
- (Optional) Brief addition to README "Current Commands" table once stable.
- The design doc `residue_hunter_scoped.md` can be left as historical reference or lightly annotated "v1 implemented per this plan (exports + generic only; on-demand; crumbs name)".

---

## 11. Risks, Open Items Post-v1, and Mitigations

**Risks (low with scoped design):**
- False positives on legitimate high-entropy files (encrypted DBs, node tarballs, etc.) → mitigated by v1 scope (only exports + generic in user dirs), filename gating, configurable threshold, advisory (not blocking).
- Performance on huge Downloads dir → size caps + early skip + name heuristic first.
- The findings list itself is sensitive → in-memory only, 0600 socket, privacy names, never logged in full.

**Post-Stage-1 work:**  
See the "Pillar 2 Full Completion Stages" section above. The remaining five stages (hunt_residue patterns, realistic materialization locations, git accidents, background scheduling, Zsh surface, etc.) are **required** for the pillar to be considered fully operational. They are not optional future ideas. Update `docs/pillars/residue_hunter_scoped.md` with a matching "Implementation Stages" header after this plan lands.

---

## 12. Estimated Effort & Sequencing

- Core residue package + detectors: 1 focused session.
- Daemon + handler + context plumbing: 0.5 session.
- CLI + status + help + config wiring: 0.5 session.
- Tests + manual E2E verification + doc updates: 0.5–1 session.
- **Total:** 2–3 focused implementation sessions for a complete, tested v1.

Can be done incrementally (package first, then wire one layer at a time) with `go test ./...` after each slice.

---

## 13. Exit Criteria (Definition of Done)

- `blastradius crumbs` works end-to-end when daemon running + feature enabled in config.
- Status shows Pillar 2 summary when findings exist.
- All existing commands and tests unaffected.
- No new persistence of sensitive data.
- Code follows project style (thin layers, hash-only, safe degradation, minimal metadata).
- Documentation updated.
- User can copy example config, enable, and see real forgotten exports flagged.

---

**This plan (revised after user review) is self-contained for an implementer.**  
Key review-driven changes incorporated:
- Removed all user-configurable "known_export_formats" / selective detector toggles. We always run the full fixed set of dangerous-artifact detectors.
- Explicitly reframed the deferred residue-sink / materialization work as **required stages 2–6** for "Pillar 2 complete" (not optional). The roadmap must be visible in both this plan and `residue_hunter_scoped.md`.

After approval of the *revised* plan, the next step is implementation (or "execute-plan").

*Plan created + revised during plan-mode exploration + user feedback round. All references are to concrete files/lines observed in the current tree.*
