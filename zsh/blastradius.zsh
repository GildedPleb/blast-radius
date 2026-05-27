# blastradius.zsh — thin broker layer (post CLI refactor)
#
# All human-visible + Zsh state/lifecycle operations go exclusively through the
# `blastradius` CLI binary (status --json, protection start/stop, redact).
# This achieves the "thinnest possible broker" goal and eliminates the old
# BR_PROTECTED / BR_RECORDER_SOCKET / direct zsocket state leakage.
#
# Narrow exception for prompt-boundary capture (NEW_WINDOW / FLUSH_WINDOW /
# RESET_HISTORY): these high-frequency operations needed for the recorder to
# actually see the user's commands are still driven via direct socket to the
# TTY-derived recorder control socket (from the recorder package). This is the
# accepted pragmatic exception documented in the CLI_REFACTOR_DESIGN plan —
# the lifecycle and status surface remain 100% CLI-mediated.
#
# When full protection is active the outer shell's precmd/preexec are
# responsible for telling the recorder about prompt boundaries and the last
# command. Until that wiring is complete in a follow-up, protection start
# gives you the socket + redact capability for manual use; automatic per-
# command windowing is not yet driven from here.

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

# Placeholder — real capture wiring (NEW_WINDOW on preexec with the command,
# FLUSH_WINDOW + possible RESET on precmd) belongs here when the Zsh side of
# the recorder protocol is re-introduced using the TTY-derived socket path.
precmd() { :; }
preexec() { :; }
