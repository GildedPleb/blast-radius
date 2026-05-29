# blastradius.zsh — thin status / HUD layer
#
# Provides lightweight wrappers and a prompt segment for visibility into the
# running Blast Radius daemon (primarily Pillar 1 tracked secrets + duplicates).
#
# All heavy lifting (discovery, scrubbing, hygiene checks) is done by the
# `blastradius` CLI + daemon. This file is intentionally minimal.

_blastradius() { command blastradius "$@"; }

blastradius_prompt_info() {
  json=$(_blastradius status --json 2>/dev/null)
  if [[ -z "$json" ]]; then
    print -n "%F{red}[BR:off]%f"
    return
  fi
  tracked=$(echo "$json" | grep -o '"tracked_hashes":[0-9]*' | cut -d: -f2)
  if [[ -n "$tracked" ]]; then
    print -n "%F{green}[BR:${tracked}]%f"
  else
    print -n "%F{red}[BR:off]%f"
  fi
}

blastradius_status() { _blastradius status; }

# Optional convenience wrappers for the main user-facing commands
blastradius_duplicates() { _blastradius duplicates; }
blastradius_scrub_history() { _blastradius scrub-history; }
blastradius_env() { _blastradius env "$@"; }
blastradius_clipboard() { _blastradius clipboard "$@"; }
