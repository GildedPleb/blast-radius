- Architecture audit
- Test Audit
- CLI audit
- Config audit
- logger audit: get all logs fucking golden!
- Bitwarden collector is still early. The Collect() implementation is functional but basic. It doesn't yet handle folders, organizations, attachments, TOTP secrets well, or have sophisticated error handling around bw states. This is the least complete area of P1.
- Versioning/compat gate for hard-coded external collectors (P1 bitwarden `bw` first): perform a version check (via `bw --version` or equivalent, after LookPath) inside Validate (and defensively before Collect work) so known-unsupported / too-old / known-bad versions produce a clean actionable error ("bitwarden: bw version X is not supported; upgrade...") instead of silent under-collection, parse failures, or weird state.
  Recommendations (current thinking):
  - Gate primarily in Validate() (perfect fit for the "prereq / IO check" seam in the Collector interface); normal Rescan path already calls Validate before Collect.
  - Policy: permissive by default (a min version where current extraction shapes stabilized + small hard-coded denylist of known-bad exact versions with comments why). Allow future/unknown versions (log the detected version) to avoid tying blastradius release cadence to bw's frequent date-based releases. Expand the set when we learn of breaks.
  - Parser: tolerant, no extra deps (strip "Bitwarden CLI ", "v", take YYYY.M.P or X.Y.Z; compare as ints).
  - Observability: log detected version on success; stash on collector for potential future exposure in collector_results / status JSON.
  - Tests: trivial via existing execBw seam (add cases for old/bad/good version strings; keep all hermetic, no sleeps).
  - Docs: loud note + example in config.example.yaml under bitwarden; update CURRENT_STATE.md, pillars framing if needed, README security if relevant; mention in the "sophisticated bw state" TODO item.
  - Error messages: actionable, point to install/upgrade commands; never any vault material (version output is safe).
  - "All interactions": covered because Validate is the gate in supported paths; direct Collect calls (mostly tests) can also call an internal ensureVersionOK().
    Punted for now (low priority vs finishing P1 basics + other audits); when picked up, treat as part of maturing the least-complete P1 area. Does not affect P4 (user commands) or P5 (stable builtins).

- [P2] (optional but powerful) Lightweight git accident detection tied to configured project roots: reflog + stash + uncommitted working tree/index. Plus optional bounded recent-commit checks (gitleaks/trufflehog style). Opt-in.

- Pillar 3 (future): Fake secrets replacement mode (research spike). Public prefixes (ghp\_, AKIA, sk- etc.), charset/length preservation via detection regex seeds, determinism (seeded rand), confirm no registry/P1 changes needed.
- Pillar 3 (future): Full safe in-place redaction for structured history formats (fish YAML-ish is the main gap; detection already works across shells). Other exotics (nushell, pwsh, etc.) as best-effort.
- Pillar 3 (future): Surface `pillar3` observability in `status --json` (last scrub time/counts/mode + summary) for symmetry with Pillar 2 and better visibility.
- [Punted] Pillar 3 in-memory tracker / cache: A small daemon-owned in-memory structure (path → last regfp + fingerprints) was considered as a fast path for repeated `scrub-history` calls within a single long-lived daemon process. Receipts already provide durability across restarts and external mutation detection. Adding an in-memory cache introduces difficult invalidation questions (time-based TTLs are too weak and risk allowing secrets to reappear; strong invalidation is hard to get right without false negatives). We are deliberately leaving this out for now. Revisit later if repeated hygiene runs become a measured performance problem.
- Automatically create and populate a config.yaml.
- Surface all useful commands to ZSH prompt functions. provide sensible defaults, sensible settings, and otherwise good recommendations for best practices. also we want to look at making it fun like a fun version where there's clever emojis that alert to items in a new and interesting way that actually maps to the usage. For instance, a lot of people will set up git in their directory in a particular way. they'll set up time and date in a particular way They'll set up their cube config status in a particular way. and for all of these things they have particular settings around the fonts, the symbols, the emojis they use. and so what we want to do is capture a new, unique, recognizable kind of branding for this.
- Add a bunch of useful commands to pillar 4 as sensible suggestions but not defaults to the config file. We have a little bit, but it'd be worthwhile to add a whole bunch more.

- Add dynamic test coverage badge to README that always shows the real trusted number from our existing coverage system. Use a GitHub Actions workflow on push to main that runs make cover, parses the per-package average produced by scripts/coverage.sh (never plain go test -cover ./...), and updates a gist JSON via schneegans/dynamic-badges-action@v1.8.0 so the shields.io endpoint badge in the README reflects current reality (with automatic color scaling). One-time setup: create a gist + GIST_TOKEN repo secret; badge URL points at the gist JSON.
