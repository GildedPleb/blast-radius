# Pillar 5 Quick User Stories (Targeted Scope)

**These 5 stories are the current focus.** Everything else dropped for now.

**Core question:** "Has a secret made it into the one place that makes it trivial to paste into the wrong window, chat, or AI prompt?"

## Condensed Principles
- Can't know intent on copy → inform fast, never auto-mutate immediately.
- Two-tier auto after detection (redact then full clear) gives intentional use window.
- Alert latency is critical: fire on *first* confirmed secret.
- Redact preferred over nuke for auto actions.
- Primitives (check/scrub/clear) + reactive monitor for awareness.

## Targeted Stories

1. **Visibility primitive (check before paste)**
   Run `blastradius clipboard` (or `check`) → tells you cleanly if known secrets are on the clipboard right now (JSON/human, no values shown). Analog to `blastradius env`.

2. **Redact/scrub primitive (keep the shape)**
   `blastradius clipboard scrub` (or `redact`) → pbpastes, removes/replaces only the known secret values with the configured `redact_placeholder` (or pillar3 fallback), pbcopies the cleaned version back. Preserves non-secret context. The placeholder is configurable under pillar5 for clipboard hygiene preference.

3. **Blunt full clear**
   `blastradius clipboard clear` (or `nuke`) → unconditionally empties the entire pasteboard. The "I want it gone now" escape hatch.

4. **Reactive alert on any copy (event-driven)**
   Background daemon monitor watches for clipboard changes (any source). On change, scans.
   **Fast path for alert:** As soon as the *first* known secret is confirmed during scanning (do not wait for full count of 10 in a giant block), immediately surface alert (notification + optional sound + future toolbar).
   "Secret(s) detected on clipboard". User can ignore (intentional copy) or act right away while the copy context is fresh. Full exact count is computed later for status/logs.

5. **Grace-period auto (two-tier, optional safety net)**
   When secret(s) detected and board content stays stable:
   - After `redact_timeout_seconds` (default 30): auto-redact the secrets in place (using the configured `redact_placeholder` under pillar5, or pillar3 fallback). This cleans the secret values while keeping structure.
   - After `full_clear_timeout_seconds` (default 60): full clear the clipboard.
   The two timeouts are independent and user-configurable (a full clear can occur without a prior redact if the user configures full_clear < redact or redact=0; this gives flexible "use window then clean" vs "use window then nuke" behaviors).
   Use case: You intentionally copy a secret to paste to AI (or a form). You paste it quickly (within the 30s window). You don't have to manually clean the clipboard — the system will auto-redact after 30s for you. If you ignore longer, full nuke at 60s. If you want the secret to survive longer for use, the timers give you a predictable window before redaction vs. total loss. Timer resets on any new clipboard content.

---

Full context, architecture, and implementation notes in `pillar5_evaluation.md`. Config supports `redact_timeout_seconds`, `full_clear_timeout_seconds`, and `redact_placeholder` (default "[REDACTED]", for both manual scrub and auto-redact) under pillar5 (plus monitor/alert toggles). The placeholder can be set independently of pillar3 for clipboard-specific preference.