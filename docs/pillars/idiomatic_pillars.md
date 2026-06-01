# Blast Radius — The Five Pillars (Idiomatic Framing)

This document reframes the five pillars around a simple, powerful distinction:

- **Pillar 1**: Finding and collecting secrets from _where they should be_.
- **Pillar 2** (new): Finding and collecting secrets from _where they should not be_.
- The remaining pillars address how secrets move, persist, and get cleaned up once they exist in the wrong places.

---

## Pillar 1 — Legitimate Secret Discovery

**Finding and collecting secrets from where they should be.**

This pillar scans the places secrets are _supposed_ to live in a controlled way:

- `.env*` files inside project roots (explicit "env" source under the logical layer)
- Configured secret sources via the logical layer (currently: hard-coded Bitwarden CLI integration + .env files)

It builds the ground truth registry of known secrets by looking in the right locations with proper scoping and ignore rules (including per-source `ignore_patterns`). Everything else in the system compares against this baseline.

**Core question it answers**: "What secrets exist in the places we deliberately put them?"

---

## Pillar 2 — Illegitimate Secret Residue (The Inversion)

**Finding and collecting secrets from where they should _not_ be.**

This is the inversion of Pillar 1.

Instead of looking in legitimate, controlled sources, it hunts for secrets that have escaped into dangerous, accidental locations — especially high-likelihood "residue sinks" that humans actually use when they fuck up:

- Exported vault dumps (Bitwarden JSON/CSV, Dashlane exports, 1Password exports, etc.) left in Downloads, Documents, Desktop, or user-specified backup locations.
- High-entropy files that look like someone exported or dumped a bunch of secrets.
- (Future scoped expansions) Editor swap files, temp debug files, and other accidental materialization residue in realistic locations (project directories, /tmp, ~/Library/Logs, etc.).

**Core question it answers**: "Where have secrets leaked into places they were never supposed to exist?"

This pillar is deliberately the mirror image of Pillar 1. Pillar 1 builds the "good" set. This one looks for the same secrets (via hash) or high-entropy material in the wild, uncontrolled filesystem.

---

## Pillar 3 — History Hygiene

**Removing secrets from places where they accumulated over time through normal use.**

Once secrets have appeared in command lines or output, they often end up in shell history. This pillar actively scrubs known secrets from history files (starting with zsh).

It is a cleanup pillar that operates on the record of past actions.

**Core question it answers**: "What secrets have we left behind in the historical record of what we typed and ran?"

---

## Pillar 4 — Runtime Environment Hygiene

**Detecting secrets that are currently live in process environments.**

This pillar periodically (or on prompt) runs user-defined commands (most commonly `printenv`) and scans their output for known secrets. It tells you, right now, whether dangerous material is sitting in your shell or tool environments.

**Hard security invariant**: Commands listed under `pillar4.commands` are always executed via direct `exec` (never through a shell). This eliminates shell metacharacter injection and arbitrary code execution risks from configuration. If you need pipes or complex logic, point at a wrapper script you control.

**Core question it answers**: "What secrets are currently readable by running `printenv` or similar introspection commands?"

This is the "can I safely run printenv right now without burning anything?" check.

---

## Pillar 5 — Clipboard Hygiene

**Catching and limiting secrets that have reached one of the most dangerous single-copy surfaces on a developer machine.**

On macOS, the clipboard is an extremely high-blast-radius location. This pillar detects when known secrets land in the clipboard and can automatically clear them after a configurable time.

**Core question it answers**: "Has a secret made it into the one place that makes it trivial to paste into the wrong window, chat, or AI prompt?"

---

## Summary — The Idiomatic Framing

| Pillar | Idiomatic Name               | Core Job                                      | "Should Be" vs "Should Not Be" |
| ------ | ---------------------------- | --------------------------------------------- | ------------------------------ |
| 1      | Legitimate Secret Discovery  | Collect secrets from controlled sources       | Where they _should_ be         |
| 2      | Illegitimate Residue Hunting | Find secrets in accidental, dangerous places  | Where they _should not_ be     |
| 3      | History Hygiene              | Remove secrets from command history           | Cleanup of past mistakes       |
| 4      | Runtime Environment Hygiene  | Detect live secrets in current environments   | "Is it in my shell right now?" |
| 5      | Clipboard Hygiene            | Limit damage on the highest-risk copy surface | Single dangerous clipboard     |

This framing makes the system feel coherent:

- Pillar 1 builds the map of the "good" world by explicitly declaring its approved on-disk secret containers (`pillar1.sources.env.options.env_file_patterns`). This declaration is authoritative.
- Pillar 2 is its dark mirror — it looks for secrets/residue in the "bad" world, but **Pillar 1 has priority and authority**. Anything P1 has claimed is automatically off-limits to P2 (enforced by the internal Classifier; never surfaced as a "conflict" in UX — the rule is documented clearly instead).
- The other three pillars deal with the common ways secrets escape the good world and how to contain or clean the damage.
