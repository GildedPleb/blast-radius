# Draft: New Pillar - Scoped Persistent Residue Hunter (Filesystem-focused)

> **v1 status (2026):** Stage 1 ("Crumbs") of the Pillar 2 implementation plan is complete. `blastradius crumbs`, fixed detectors, config `residue_hunter`, daemon + status integration all shipped. See `pillar2-implementation-plan.md` for the required 6-stage completion roadmap (hunt_residue patterns, materialization roots, git, scheduling, etc. are **not optional** for "Pillar 2 fully operational").

## Name Ideas
- Pillar X: Persistent Secret Residue Hunter
- Pillar X: Forgotten Export / Dump Auditor
- Pillar X: High-Risk Directory Secret Residue Scanner

## Core Principle (User-Refined Scope)
Do **not** ask for Full Disk Access.
Only scan "high-likelihood dump locations" that an attacker would already target:
- ~/Downloads
- ~/Documents  
- ~/Desktop
- User-configurable additions (e.g. ~/backups, specific project dirs, external volumes when mounted)

Goal: Detect real-world dangerous artifacts like:
- Bitwarden JSON/CSV exports
- Dashlane exports
- 1Password .1pif or .csv exports
- Generic "passwords.txt", "secrets.json", "creds.csv" files with high entropy or known structures
- Old .env files with massive secret counts sitting in wrong places

This is purely advisory/passive: find the file, hash interesting parts, check against known registry or high-entropy heuristics, surface a nag in the HUD: "Found likely vault export at ~/Downloads/bitwarden_export_2023.json — you should delete or secure this."

## Why This Surface Is Different
- Not live env (Pillar 5)
- Not command history (Pillar 4)
- Not clipboard (Pillar 2)
- Not duplicates across projects (Pillar 1)
- It's "I created a giant secret dump file once and forgot it exists on disk"

## Security Trade-offs (Scoped Version)
**Much better than full disk:**
- Attacker with user-level access is already very likely to look in Downloads/Documents/Desktop anyway.
- No new broad permissions required beyond what the user already grants for normal file access.
- Can run with standard user permissions.

**Remaining risks:**
- The list of found residue files is itself sensitive.
- Must store results carefully (hashes only, or encrypted).
- Still creates a program whose output is "here are all the dangerous secret files on your machine."

## Proposed Config Addition

```yaml
# Scoped Persistent Residue Hunter (new pillar)
residue_hunter:
  enabled: true
  # High-likelihood locations only. No full disk.
  target_dirs:
    - "~/Downloads"
    - "~/Documents"
    - "~/Desktop"
    # User can add more (e.g. external drives when mounted, backup folders)
    - "~/backups"
  # How often to scan these locations (in hours). Default: once per day.
  scan_interval_hours: 24
  # Known dangerous export formats to fingerprint
  known_export_formats:
    - bitwarden_json
    - bitwarden_csv
    - dashlane
    - onepassword_1pif
    - generic_high_entropy_json
  # Minimum number of high-entropy values before considering a file "suspicious"
  min_high_entropy_hits: 3
  # Whether to also flag files with names that strongly suggest secret dumps
  flag_suspicious_filenames: true
```

## Detection Strategy (Practical, Not Full Kernel Scan)

1. Walk only the configured target_dirs (using existing discovery patterns with skips).
2. For each regular file:
   a. Check filename heuristics ("export", "backup", "passwords", "creds", "bitwarden", "dashlane", dates, etc.).
   b. For promising files, do lightweight parsing:
      - If JSON/CSV: look for known Bitwarden/Dashlane field structures + high entropy in "value"/"password" fields.
      - Generic: count high-entropy strings (base64-looking, long random strings).
   c. Hash the suspicious values and check against the central secret registry.
3. Record findings with location (privacy-friendly display name), last modified time, and confidence.
4. Surface via existing HUD / status mechanisms: "3 suspicious secret dump files found. Oldest: 2024-03-12 in ~/Downloads".

## Integration Points (Reuse Existing Code)
- Reuse `internal/discovery` Scanner patterns (ignore files, skip_dirs).
- Reuse the central `registry.Registry` for hash lookups.
- Reuse daemon + CLI patterns for running on schedule or on-demand.
- Reuse config loading.

## Open Questions for Implementation
- How aggressively to parse vs just filename + entropy?
- Should we ever attempt secure deletion suggestions, or strictly advisory?
- How to handle false positives on legitimate high-entropy files (encrypted databases, etc.)?
- Should scans be user-triggered only, or background with rate limiting?

This scoped version dramatically reduces the "the tool is now the problem" risk while still catching the most common human failure mode.

## Incorporating the Original "Residue Sinks" Vision (Scoped)

The original broader idea was to hunt for *residue* left behind when secrets are materialized — not just clean vault exports, but the messy leftovers:

- Editor swap/backup files (Vim .swp, .swo, Emacs #*# and .#*, VS Code .~*, etc.)
- Random temp files with high entropy
- Shell history fragments or backup files
- Git objects or loose objects in weird places
- Core dumps or crash reports
- Any file that looks like someone was debugging and accidentally wrote secrets to disk

### How to Fold This In Without Losing the Scoped Safety

We can bring a meaningful amount of the "residue sinks" flavor back while staying strictly inside the user-approved high-likelihood folders:

1. **Within the same target_dirs**, add a second scanning pass (or combined pass) that looks for *residue patterns* in addition to full export formats.

2. Add config for "residue awareness":

```yaml
residue_hunter:
  enabled: true
  target_dirs:
    - "~/Downloads"
    - "~/Documents"
    - "~/Desktop"

  # Existing export-focused stuff...

  # NEW: Residue sink hunting inside the allowed folders
  hunt_residue: true

  # File name patterns that often indicate residue (in addition to export names)
  residue_filename_patterns:
    - "*.swp"
    - "*.swo"
    - "*~"
    - ".#*"
    - "*.bak"
    - "*_backup*"
    - "*temp*secret*"
    - "*crash*.log"
    - "core.*"

  # When we see these patterns + high entropy, treat them as residue
  residue_min_entropy_hits: 2   # Lower threshold than full exports because these are usually smaller

  # Also look for high-entropy blobs in files that have "temp", "debug", "dump" in the name
  # even if they don't match known export formats.
  scan_generic_high_entropy_in_temp_files: true
```

### Benefits of This Hybrid

- Still only walks the safe, user-controlled locations.
- Captures the original vision of "secret materialization leaves messy filesystem residue."
- Catches real cases like:
  - Someone did `printenv > /tmp/debug.txt` or `vim /tmp/creds` and left the swap file.
  - Exported a vault, then used an editor on it and left .swp files.
  - Accidentally `cat secrets.json >> some_temp_file` in Downloads.
- Gives more "I fucked up and left traces" signals, which aligns with the materialization residue paradigm you liked earlier.

### Trade-off When Adding Residue Hunting

- Slightly higher false positive rate (legitimate temp files can have entropy).
- Still manageable because we're scoped to a small number of directories.
- We can make residue detection *lighter* than full export parsing (just filename + entropy count, no deep format parsing required).

This way we get some of the spirit of the original "look in residue sinks for high-entropy material" idea without ever needing broad filesystem access or becoming a general-purpose secret scanner.

The pillar remains advisory: "Hey, there's a Vim swap file with what looks like secrets in ~/Downloads from three months ago. You should probably delete that."


## Realistic Locations for Different Types of Residue (Honest Assessment)

The original vision mentioned "editor swap/backup files, temp directories, git objects, shell history fragments, core dumps."

User feedback: These do **not** primarily live in ~/Downloads, ~/Documents, or ~/Desktop.

### Where Editor Swap Files Actually Live

- **Vim**: Almost always in the *same directory* as the file being edited.
  - Example: Editing `~/.zshrc` → `~/.zshrc.swp` right next to it.
  - Editing `~/projects/myapp/config.yaml` → `~/projects/myapp/config.yaml.swp`

- **Neovim**: Defaults to `~/.local/share/nvim/swap/`

- **Emacs**: 
  - Auto-save files (`#filename#`) in the same directory.
  - Auto-save list directory: `~/.emacs.d/auto-save-list/`

- **JetBrains IDEs** (IntelliJ, GoLand, etc.): Local History and caches in `~/Library/Application Support/JetBrains/` or project `.idea/` folders.

- **VS Code**: Does not use traditional swap files. It has its own workspace storage.

**Conclusion**: Editor swap files are a *project directory + home config* surface, not a Downloads/Desktop surface.

### Where Random Temp/Debug Files Actually Live

People debugging secrets typically do things like:

- `printenv | grep SECRET > /tmp/debug.txt`
- `cat .env > ~/tmp/creds.dump`
- `vim /tmp/scratch_creds && rm /tmp/scratch_creds` (swap may linger briefly)
- Writing to current working directory in a project: `./debug.env`, `temp_secrets.json`
- `~/Library/Logs/`, `~/.cache/`, project-specific `.tmp/` or `debug/` folders

Primary realistic locations:
- `/tmp/` and `/var/tmp/` (and macOS `/private/tmp/`)
- `~/tmp/`, `~/.tmp/`
- Inside project directories (very common)
- `~/Library/Logs/`
- `~/.cache/`

### Git History Feasibility

This is interesting but has clear boundaries:

**Cheap and high-value to scan:**
- Uncommitted changes (working tree + index)
- Git reflog (recent "I reset that commit" mistakes)
- Stashes

**Expensive and noisy:**
- Full scan of `.git/objects` for high-entropy blobs across history.
  - Packfiles make this slow.
  - Binaries, images, and compiled artifacts create massive false positives.
  - On a medium repo this can take noticeable time.

**Fundamental limitation:**
- Once a secret has been pushed to a remote, local git scanning has limited value for "burned" status (it's already out).
- However, for *local* blast radius (your machine, your backups, your Time Machine), local history still matters.

**Practical recommendation for this pillar:**
- Do **not** try to do deep historical object scanning by default.
- Offer an opt-in "scan git history for this project" that focuses on:
  - Reflog + stash + uncommitted
  - Optionally a bounded recent commit range with a good tool (gitleaks/trufflehog style)
- Tie it to the existing `project_roots` configuration rather than the "Downloads/Documents" scope.

### Revised Mental Model for the Pillar

It may make sense to think of this pillar as having **two somewhat distinct jobs** even if they share code:

1. **Vault Export / Bulk Dump Hunter** (scoped to Downloads + Documents + Desktop + user additions)
   - Primary focus on exported password manager files.
   - This is the high-confidence, high-value, low-false-positive part.

2. **Accidental Materialization Residue Hunter** (scoped to project directories + standard temp locations + git repos)
   - This is where the original "residue sinks" vision actually lives.
   - Editor swaps, temp debug files, git reflog accidents, etc.

Trying to force both into the exact same narrow folder list creates a mismatch, as you correctly identified.

---

## Implementation Stages (Added 2026)

This document is the historical design source. The concrete implementation plan lives in [pillar2-implementation-plan.md](pillar2-implementation-plan.md). For visibility, the agreed staged rollout of Pillar 2 is:

**Stage 1 (current work — "Crumbs" MVP)**  
Vault export formats (Bitwarden JSON/CSV, Dashlane, 1Password, generic high-entropy) + suspicious filename heuristics, strictly inside the user-controlled `target_dirs` (Downloads/Documents/Desktop + additions). On-demand only via `blastradius crumbs`. Lightweight summary in `status`. `residue_hunter.enabled` + `target_dirs` only in config. All detectors are always-on when the feature is enabled (no selective format toggles).

**Stage 2**  
Inside the *same* `target_dirs`, add `hunt_residue` support: editor swap patterns (`*.swp`, `*.swo`, `*~`, `.#*`, `*_backup*`, temp/debug/crash files) with lower entropy threshold. Still advisory.

**Stage 3**  
Expand surface to realistic materialization locations (project dirs, `/tmp`, `~/tmp`, `~/.cache`, `~/Library/Logs`, etc.). Likely requires additional config surface or reuse of `project_roots`.

**Stage 4**  
Lightweight git surface (reflog + stash + uncommitted) + optional bounded history checks, tied to project roots.

**Stage 5**  
Background scheduling or fsnotify reactivity for the hunter.

**Stage 6**  
Zsh HUD integration + any final polish. (Secure delete suggestions remain strictly advisory forever.)

Pillar 2 is not "done" until Stage 6. The high-confidence export hunter (Stage 1) is valuable and shippable by itself, but the full "residue sinks" vision requires all stages.

See the implementation plan for the detailed file-by-file breakdown of Stage 1.
