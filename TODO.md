- The skip directories and ignore files are kind of stupid. And also, that should just be the single source of truth. There should not be strong defaults, et cetera.
- Automatically create and populate a config.yaml.
- (Addressed) High-risk command context (printenv, etc.) now uses the unified detection package for proper candidate extraction instead of treating entire output as sensitive.
- Documentation audit
- File Structure audit
- Security Audit
- Architecture audit
- Test Audit
- logger audit
- Backwards compatability audit (e.g. we can fully drop all backwards compatibility because we havent released any software yet, lol)
- Bitwarden collector is still early. The Collect() implementation is functional but basic. It doesn't yet handle folders, organizations, attachments, TOTP secrets well, or have sophisticated error handling around bw states. This is the weakest part of the "done" story.
- (DONE) Pillar 1 / Pillar 2 coordination + authority model implemented.
  See the approved plan (session 019e83e0...) and the loud documentation in
  config.example.yaml + the pillar docs. P1 env_file_patterns now exist,
  pillar2 uses dirs[] + per-dir files[], internal/policy.Classifier enforces
  "P1 has authority and priority over P2" (the three stories all work),
  and legacy behavior is fully preserved. No new CLI/status surfaces were added.
