- The skip files and ignore files are kind of stupid. rather the skip directories and ignore files are kind of stupid. And also, that should just be the single source of truth. There should not be strong defaults, et cetera.
- Automatically create and populate a config.yaml.
- (Addressed) High-risk command context (printenv, etc.) now uses the unified detection package for proper candidate extraction instead of treating entire output as sensitive.
- Documentation audit
- File Structure audit
- Security Audit
- Architecture audit
- Test Audit
- logger audit
- Backwards compatability audit (e.g. we can fully drop all backwards compatibility because we havent released any software yet, lol)
- 1. Bitwarden collector is still early
     The Collect() implementation is functional but basic. It doesn't yet handle folders, organizations, attachments, TOTP secrets well, or have sophisticated error handling around bw states. This is the weakest part of the "done" story.
- Kill this: 4. Migration UX is still a bit messy
  Users can now have the same settings in two places (top-level + pillar1.sources.env.options). The fallback logic helps, but it's not elegant long-term.
