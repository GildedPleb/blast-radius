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
}

# Human-readable status (wrapper)
blastradius_status() {
    _blastradius status
}

# === Hook Skeletons (for future Pillar integration) ===

# Called before every command execution
blastradius_preexec() {
    # Placeholder for future use:
    # - Detect sensitive commands (printenv, env, cat .env*)
    # - Set internal state for post-command redaction (Pillar 3)
    :
}

# Called after every command completes (before new prompt)
blastradius_precmd() {
    # Placeholder for future use:
    # - Trigger history hygiene (Pillar 4)
    # - Update any cached HUD state
    :
}

# Optional: Auto-install hooks if user wants (advanced)
blastradius_install_hooks() {
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec blastradius_preexec
    add-zsh-hook precmd  blastradius_precmd
    echo "Blast Radius hooks installed (preexec + precmd)"
}

# Helpful message on source
if [[ -o interactive ]]; then
    # Only show in interactive shells
    :
fi