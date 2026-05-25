
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

# Composable secret status indicator for user prompts
# Returns ⚠️ when unscrubbed secrets exist, ✓ when clean
blastradius_secret_status() {
    if (( BR_PROTECTED )); then
        if (( BR_SESSION_HAS_SECRETS )); then
            print -n " %F{red}⚠%f"
        else
            print -n " %F{green}✓%f"
        fi
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
    BR_FLUSH_COUNT=0
    BR_HAS_PENDING_SECRET=0
    BR_SESSION_HAS_SECRETS=0
    BR_WARNING_COUNT=0
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
    BR_FLUSH_COUNT=0
    BR_HAS_PENDING_SECRET=0
    BR_SESSION_HAS_SECRETS=0
    BR_WARNING_COUNT=0
    unset BR_RECORDER_SOCKET BR_INSIDE_RECORDER
    echo "Exiting Blast Radius Protected Mode."
}

# =============================================================================
# br-clear: clear terminal + replay redacted history (MVP)
# =============================================================================
br-clear() {
    (( BR_PROTECTED )) || { echo "Not in protected mode."; return 1; }
    local mode custom preserve
    local cfg_json
    cfg_json=$(_blastradius config redaction --json 2>/dev/null || true)
    mode=$(echo "$cfg_json" | grep -o '"redaction_mode":"[^"]*"' | cut -d'"' -f4)
    custom=$(echo "$cfg_json" | grep -o '"custom_replacement":"[^"]*"' | cut -d'"' -f4)
    preserve=$(echo "$cfg_json" | grep -o '"preserve_colors":[^,]*' | cut -d: -f2 | tr -d ' "')
    [[ -z "$mode" ]] && mode="replace"
    [[ -z "$custom" ]] && custom="[REDACTED]"
    [[ -z "$preserve" ]] && preserve=true
    clear
    _br_recorder_cmd "REPLAY_REDACTED" "$mode $custom $preserve"
    BR_FLUSH_COUNT=0
    BR_HAS_PENDING_SECRET=0
    BR_SESSION_HAS_SECRETS=0
    BR_WARNING_COUNT=0
}

# Alias for design-doc consistency
blastradius_clear() { br-clear "$@"; }

# =============================================================================
# Recorder socket helpers (robust zsocket + auto window flush)
# =============================================================================
_br_recorder_cmd() {
    local cmd="$1" extra="$2"
    [[ -z "$BR_RECORDER_SOCKET" ]] && return 1
    zmodload zsh/net/socket 2>/dev/null || return 1
    zsocket "$BR_RECORDER_SOCKET" 2>/dev/null || return 1
    local fd=$REPLY
    if [[ -n "$extra" ]]; then
        print -u $fd "$cmd $extra"
    else
        print -u $fd "$cmd"
    fi
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
    local data flag
    data=$(_br_recorder_cmd "FLUSH_WINDOW")
    # Last line of response is now the secret flag (HAS_SECRET / NO_SECRET)
    flag=${data##*$'\n'}
    data=${data%$flag}
    if [[ "$flag" == HAS_SECRET* ]]; then
        BR_HAS_PENDING_SECRET=1
        BR_SESSION_HAS_SECRETS=1
        BR_WARNING_COUNT=0
    fi
    # Treat every line as IO: immediately hash via daemon, discard plaintext
    while IFS= read -r line; do
        [[ -n "$line" ]] && _blastradius check-hash "$(print -rn -- "$line" | sha256sum | cut -d' ' -f1)" >/dev/null 2>&1 || true
    done <<< "$data"
    if [[ -n "$BR_LAST_COMMAND" ]]; then
        _br_recorder_cmd "NEW_WINDOW $BR_LAST_COMMAND"
        unset BR_LAST_COMMAND
    else
        _br_recorder_cmd "NEW_WINDOW"
    fi
}

blastradius_preexec() {
    # Capture command for later association with the recording window
    BR_LAST_COMMAND="$1"

    # Check for clear/reset commands that should discard protected history
    if (( BR_PROTECTED )); then
        local cfg_json cmds cmd
        cfg_json=$(_blastradius config redaction --json 2>/dev/null || true)
        cmds=$(echo "$cfg_json" | grep -o '"clear_reset_commands":\[[^]]*\]' | sed 's/.*\[\([^]]*\)\].*/\1/' | tr ',' ' ')
        for cmd in ${(z)cmds}; do
            cmd=${cmd//\"/}
            if [[ "$1" == $~cmd* ]]; then
                printf 'RESET_HISTORY\n' | timeout 1 zsocket "$BR_RECORDER_SOCKET" 2>/dev/null || true
                BR_FLUSH_COUNT=0
                BR_HAS_PENDING_SECRET=0
                BR_SESSION_HAS_SECRETS=0
                BR_WARNING_COUNT=0
                break
            fi
        done
    fi
}

# Simple buffer counter for automated redaction (MVP)
typeset -g BR_FLUSH_COUNT=0
typeset -g BR_SESSION_HAS_SECRETS=0
typeset -g BR_WARNING_COUNT=0

blastradius_precmd() {
    if (( BR_PROTECTED )); then
        local auto buffer warning_persist
        local cfg_json
        cfg_json=$(_blastradius config redaction --json 2>/dev/null || true)
        auto=$(echo "$cfg_json" | grep -o '"automated":[^,]*' | cut -d: -f2 | tr -d ' "')
        buffer=$(echo "$cfg_json" | grep -o '"buffer":[^,]*' | cut -d: -f2 | tr -d ' "')
        warning_persist=$(echo "$cfg_json" | grep -o '"warning_persist":[^,]*' | cut -d: -f2 | tr -d ' "')
        [[ -z "$auto" ]] && auto=1
        [[ -z "$buffer" || "$buffer" -lt 1 ]] && buffer=1
        [[ -z "$warning_persist" || "$warning_persist" -lt 1 ]] && warning_persist=$buffer

        if (( auto )); then
            (( BR_FLUSH_COUNT++ ))
            if (( BR_FLUSH_COUNT >= buffer )); then
                if (( BR_HAS_PENDING_SECRET )); then
                    local mode custom preserve
                    local cfg_json
                    cfg_json=$(_blastradius config redaction --json 2>/dev/null || true)
                    mode=$(echo "$cfg_json" | grep -o '"redaction_mode":"[^"]*"' | cut -d'"' -f4)
                    custom=$(echo "$cfg_json" | grep -o '"custom_replacement":"[^"]*"' | cut -d'"' -f4)
                    preserve=$(echo "$cfg_json" | grep -o '"preserve_colors":[^,]*' | cut -d: -f2 | tr -d ' "')
                    [[ -z "$mode" ]] && mode="replace"
                    [[ -z "$custom" ]] && custom="[REDACTED]"
                    [[ -z "$preserve" ]] && preserve=true
                    clear
                    _br_recorder_cmd "REPLAY_REDACTED" "$mode $custom $preserve"
                    BR_HAS_PENDING_SECRET=0
                    BR_SESSION_HAS_SECRETS=0
                    BR_WARNING_COUNT=0
                fi
                BR_FLUSH_COUNT=0
            fi
        fi

        # Warning persist counter (separate from automation buffer)
        if (( BR_SESSION_HAS_SECRETS )); then
            (( BR_WARNING_COUNT++ ))
            if (( BR_WARNING_COUNT > warning_persist )); then
                BR_SESSION_HAS_SECRETS=0
                BR_WARNING_COUNT=0
            fi
        fi
    else
        BR_FLUSH_COUNT=0
        BR_HAS_PENDING_SECRET=0
        BR_SESSION_HAS_SECRETS=0
        BR_WARNING_COUNT=0
    fi

    # Pillar 5 - automatic runtime hygiene checks (per-command opt-in)
    if (( BR_PROTECTED )); then
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
    echo "  br-stop      → Exit protected mode"
    echo "  br-toggle    → Toggle protected mode"
    echo "  br-clear     → Clear terminal + rebuild redacted view"
    echo "  blastradius_status"
    echo "  blastradius env [name]     → Run Pillar 5 check"
    echo "  blastradius clipboard clear → Clear clipboard (Pillar 2)"
}

# Auto-detect recorder on source (robust entry)
if [[ -n "$BR_INSIDE_RECORDER" ]]; then
    BR_PROTECTED=1
    BR_RECORDER_SOCKET="${BR_RECORDER_SOCKET:-/tmp/br-recorder.sock}"
    BR_SESSION_HAS_SECRETS=0
    BR_WARNING_COUNT=0
fi

# =============================================================================
# Auto-protected mode (Wrapper 2) + br-toggle (Wrapper 1)
# =============================================================================

_br_auto_start_protected() {
    (( BR_PROTECTED )) && return 0

    local cfg_json auto
    cfg_json=$(_blastradius config redaction --json 2>/dev/null || true)
    auto=$(echo "$cfg_json" | grep -o '"automated":[^,]*' | cut -d: -f2 | tr -d ' "')
    [[ "$auto" != "true" ]] && return 0

    # Per-terminal socket for multi-terminal support
    local tty_name
    tty_name=$(tty 2>/dev/null | tr '/ ' '__')
    BR_RECORDER_SOCKET="${BR_RECORDER_SOCKET:-/tmp/br-recorder-${tty_name:-$$}.sock}"
    export BR_RECORDER_SOCKET BR_INSIDE_RECORDER=1

    if _blastradius recorder start >/dev/null 2>&1; then
        BR_PROTECTED=1
        BR_FLUSH_COUNT=0
        BR_HAS_PENDING_SECRET=0
        BR_SESSION_HAS_SECRETS=0
        BR_WARNING_COUNT=0
    fi
}

br-toggle() {
    if (( BR_PROTECTED )); then
        br-stop
    else
        br-start
    fi
}

# Attempt auto-protected mode on interactive shell startup
if [[ -o interactive && -z "$BR_INSIDE_RECORDER" ]]; then
    _br_auto_start_protected
fi

# Clean shutdown of recorder on shell exit
zshexit() {
    if (( BR_PROTECTED && -n "$BR_RECORDER_SOCKET" )); then
        printf 'STOP\n' | timeout 1 zsocket "$BR_RECORDER_SOCKET" 2>/dev/null || true
    fi
}

# Auto message when sourced
if [[ -o interactive ]]; then
    echo "Blast Radius loaded. Run 'blastradius_install' to activate hooks."
fi