# blastradius.zsh (phase 4 thin broker, CLI-only, formatting preserved)
_blastradius() { command blastradius "$@"; }
blastradius_prompt_info() {
  json=$(_blastradius status --json 2>/dev/null)
  if [[ -z "$json" ]]; then print -n "%F{red}[BR:off]%f"; return; fi
  if echo "$json" | grep -q '"protected":true'; then
    tracked=$(echo "$json" | grep -o '"tracked_hashes":[0-9]*' | cut -d: -f2)
    print -n "%F{green}[BR:${tracked:-0}]%f"
  else
    print -n "%F{red}[BR:off]%f"
  fi
}
blastradius_status() { _blastradius status; }
blastradius_protection_start() { _blastradius protection start; }
blastradius_protection_stop() { _blastradius protection stop; }
blastradius_redact() { _blastradius redact "$@"; }
precmd() { :; }
