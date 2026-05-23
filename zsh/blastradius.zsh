
# blastradius.zsh
#
# Blast Radius - Zsh integration for Ambient OPSEC HUD
#
# Usage:
#   1. Source this file in your ~/.zshrc:
#        source /path/to/blast-radius/zsh/blastradius.zsh
#
#   2. Add to your prompt (example for plain PROMPT):
#        PROMPT='$(blastradius_prompt_info)'$PROMPT
#
#   3. Or use with Powerlevel10k / Starship via custom segment.
#
# This file provides:
#   - blastradius_prompt_info()   → Compact status for prompt
#   - blastradius_status()        → Human readable status
#   - Basic precmd / preexec hook skeletons (for future pillars)
#
# Philosophy: Keep it lightweight, composable, and non-intrusive.

# Main command wrapper (respects PATH)
_blastradius() {
    command blastradius "$@"
}

# Returns 0 if daemon is running, 1 otherwise (fast check)
blastradius_is_running() {
    _blastradius status --json >/dev/null 2>&1
}

# Prints a compact prompt segment
# Example output: [BR:142|ok]  or  [BR:off]
blastradius_prompt_info() {
    local json status scan tracked color reset

    json=$(_blastradius status --json 2>/dev/null)
    if [[ $? -ne 0 || -z "$json" ]]; then
        # Daemon not running or error
        print -n "%F{red}[BR:off]%f"
        return
    fi

    # Very lightweight JSON extraction without jq (KISS for v1)
    status=$(echo "$json" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    tracked=$(echo "$json" | grep -o '"tracked_hashes":[0-9]*' | cut -d':' -f2)
    scan=$(echo "$json" | grep -o '"scan_state":"[^"]*"' | cut -d'"' -f4)

    if [[ "$status" == "ok" ]]; then
        color="%F{green}"
    else
        color="%F{yellow}"
    fi

    reset="%f"

    if [[ -n "$tracked" && "$tracked" != "0" ]]; then
        print -n "${color}[BR:${tracked}|${scan:-ok}]${reset}"
    else
        print -n "${color}[BR:ok]${reset}"
    fi

    # Pillar 2 clipboard status (simple icon)
    local clip_json clip_status
    clip_json=$(_blastradius clipboard status --json 2>/dev/null)
    clip_status=$(echo "$clip_json" | grep -o '"known":[^,]*' | head -1 | cut -d':' -f2)
    if [[ "$clip_status" == "true" ]]; then
        print -n " %F{red}[CLIP:⚠]%f"
    else
        print -n " %F{green}[CLIP:ok]%f"
    fi
}

# Human-readable status (wrapper)
blastradius_status() {
    if (( BR_PROTECTED )); then
        echo "🟢 INSIDE Blast Radius Protected Mode"
    else
        echo "🔴 OUTSIDE Blast Radius Protected Mode (normal)"
    fi
}

# =============================================================================
# Enter Protected Mode (now uses Go PTY recorder)
# =============================================================================
br-start() {
    if (( BR_PROTECTED )); then
        echo "Already inside protected mode."
        return 0
    fi

    BR_RECORDER_SOCKET="${BR_RECORDER_SOCKET:-/tmp/br-recorder.sock}"
    export BR_RECORDER_SOCKET BR_INSIDE_RECORDER=1

    if ! _blastradius recorder start >/dev/null 2>&1; then
        echo "Failed to start recorder."
        return 1
    fi

    BR_PROTECTED=1
    echo "Entering Blast Radius Protected Mode (Go PTY recorder)..."
    echo "Control socket: $BR_RECORDER_SOCKET"
}

# =============================================================================
# Exit Protected Mode
# =============================================================================
br-stop() {
    if (( BR_PROTECTED == 0 )); then
        echo "Not inside protected mode."
        return 0
    fi

    if [[ -n "$BR_RECORDER_SOCKET" ]]; then
        printf 'STOP\n' | timeout 1 zsocket "$BR_RECORDER_SOCKET" 2>/dev/null || true
    fi

    BR_PROTECTED=0
    unset BR_RECORDER_SOCKET BR_INSIDE_RECORDER
    echo "Exiting Blast Radius Protected Mode."
}

# =============================================================================
# Recorder socket helpers (robust zsocket + auto window flush)
# =============================================================================
_br_recorder_cmd() {
    local cmd="$1"
    [[ -z "$BR_RECORDER_SOCKET" ]] && return 1
    zmodload zsh/net/socket 2>/dev/null || return 1
    zsocket "$BR_RECORDER_SOCKET" 2>/dev/null || return 1
    local fd=$REPLY
    print -u $fd "$cmd"
    if [[ "$cmd" == "FLUSH_WINDOW" ]]; then
        local line
        while read -r -u $fd line; do
            [[ "$line" == "ERR" || "$line" == "OK" ]] && break
            _blastradius check-hash "$line" >/dev/null 2>&1 || true
        done
    elif [[ "$cmd" == "REPLAY_REDACTED" ]]; then
        local line
        while read -r -u $fd line; do
            [[ "$line" == "OK" ]] && break
            print -r -- "$line"
        done
    fi
    exec {fd}>&-
}

_br_flush_window() {
    (( BR_PROTECTED )) || return 0
    local data
    data=$(_br_recorder_cmd "FLUSH_WINDOW")
    # Treat every line as IO: immediately hash via daemon, discard plaintext
    while IFS= read -r line; do
        [[ -n "$line" ]] && _blastradius check-hash "$(print -rn -- "$line" | sha256sum | cut -d' ' -f1)" >/dev/null 2>&1 || true
    done <<< "$data"
    _br_recorder_cmd "NEW_WINDOW"
}

blastradius_preexec() {
    # no-op (protected mode uses recorder PTY)
}

blastradius_precmd() {
    _br_flush_window

    # Pillar 5 - automatic runtime hygiene checks (per-command opt-in)
    if (( BR_PROTECTED )); then
        # Only run commands that have auto_on_prompt: true (currently only default-env)
        _blastradius env default-env >/dev/null 2>&1 || true
    fi
}

# =============================================================================
# Installation
# =============================================================================
blastradius_install() {
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec blastradius_preexec
    add-zsh-hook precmd  blastradius_precmd

    echo "Blast Radius hooks installed."
    echo "Commands:"
    echo "  br-start     → Enter protected recording mode (Go PTY)"
    echo "  br-clear     → Clear terminal + rebuild redacted view"
    echo "  blastradius_status"
    echo "  blastradius env [name]     → Run Pillar 5 check"
    echo "  blastradius clipboard clear → Clear clipboard (Pillar 2)"
}

# Auto-detect recorder on source (robust entry)
if [[ -n "$BR_INSIDE_RECORDER" ]]; then
    BR_PROTECTED=1
    BR_RECORDER_SOCKET="${BR_RECORDER_SOCKET:-/tmp/br-recorder.sock}"
fi

# Auto message when sourced
if [[ -o interactive ]]; then
    echo "Blast Radius loaded. Run 'blastradius_install' to activate hooks."
fi