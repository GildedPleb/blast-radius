#!/usr/bin/env bash
#
# scripts/coverage.sh
#
# THE CONTAINED UGLY THING
# ============================================================================
# This is the *single* place that knows:
#   - How to build coverage-instrumented test binaries (go test -c -cover)
#   - Per-package collection + execution-only timing
#   - The 5s wall-time gate + .coverage-failed early-abort sentinel for parallel safety
#   - Averaging + 80% strict gate decision (for test-cover/ci/check)
#   - Rich vs quiet output formatting
#
# EVERYTHING about the Go toolchain bug workaround + the <5s CI gate lives here.
#
# IF YOU ARE ONLY ADDING A PACKAGE OR A NORMAL TARGET:
#   - Do not read or edit this file.
#   - The only thing that matters is the PACKAGES list + PKG_* block in the Makefile.
#   - This script is called as a black box from the declarative coverage targets.
#
# Single source of truth for package names stays in the Makefile.
# This script receives the list (or individual name + pre-built binary) at runtime.
# ============================================================================

set -euo pipefail

# --- build: the one and only way to produce coverage.*.test artifacts ---
build() {
    local pkg="${1:-}"
    local name="${2:-}"
    if [[ -z "$pkg" ]]; then
        echo "ERROR: PKG is required (e.g. PKG=./internal/cli)" >&2
        exit 1
    fi
    if [[ -z "$name" ]]; then
        echo "ERROR: NAME is required (e.g. NAME=cli)" >&2
        exit 1
    fi
    rm -f "coverage.${name}.test"
    go test -c -cover -o "coverage.${name}.test" "$pkg"
    chmod +x "coverage.${name}.test"
}

# --- collect: rich path used by `make cover` and `make cover-<pkg>` ---
collect() {
    local name="$1"
    local start end elapsed cov
    local log="coverage.${name}.log"
    local out="coverage.${name}.out"
    local testbin="coverage.${name}.test"

    start=$(date +%s)
    if ! "./$testbin" -test.count=1 -test.timeout=5s -test.coverprofile="$out" >"$log" 2>&1; then
        echo "=== FAILURE: captured output tail for ${name} (last 200 lines) ==="
        tail -200 "$log" || cat "$log"
        echo "=== end of tail ==="
        rm -f "$log"
        exit 1
    fi
    rm -f "$log"
    end=$(date +%s)
    elapsed=$((end - start))

    cov=$(go tool cover -func="$out" 2>/dev/null \
        | grep '^total:' \
        | grep -o '[0-9][0-9.]*%' \
        | tr -d '%' || true)
    [ -n "$cov" ] || cov=0

    echo "${name}: ${cov}% (${elapsed}s)"
    echo ""
    echo "=== Detailed function + statement coverage for ${name} ==="
    go tool cover -func="$out" 2>/dev/null || true
}

# --- collect-quiet: gate path used only by test-cover / ci / check ---
collect_quiet() {
    local name="$1"
    if [ -f .coverage-failed ]; then exit 1; fi

    local start end elapsed cov
    local log="coverage.${name}.log"
    local out="coverage.${name}.out"
    local testbin="coverage.${name}.test"

    start=$(date +%s)
    if ! "./$testbin" -test.count=1 -test.timeout=5s -test.coverprofile="$out" >"$log" 2>&1; then
        echo "=== FAILURE: captured output tail for ${name} (last 200 lines) ==="
        tail -200 "$log" || cat "$log"
        echo "=== end of tail ==="
        rm -f "$log"
        exit 1
    fi
    rm -f "$log"
    end=$(date +%s)
    elapsed=$((end - start))

    if [ "$elapsed" -gt 5 ]; then
        touch .coverage-failed
        echo ""
        echo "=== PACKAGE FAILURE ==="
        echo "Package : ${name}"
        echo "Problem : Wall time ${elapsed}s exceeded the 5s limit (execution only)"
        echo "Action  : Aborting remaining packages"
        echo ""
        exit 1
    fi

    cov=$(go tool cover -func="$out" 2>/dev/null | grep '^total:' | grep -o '[0-9][0-9.]*%' | tr -d '%' || true)
    [ -n "$cov" ] || cov=0
    echo "${name}: ${cov}% (${elapsed}s)"
}

# --- summarize: final block for `make cover` (human, no 80% gate) ---
summarize() {
    # $PACKAGES env var (space-separated short names) is required
    local sum=0 cnt=0 p pct maj min tenths avg_t whole dec

    for p in $PACKAGES; do
        pct=$(go tool cover -func="coverage.${p}.out" 2>/dev/null \
            | grep '^total:' \
            | grep -o '[0-9][0-9.]*%' \
            | tr -d '%' || true)
        [ -n "$pct" ] || pct=0
        maj=$(echo "$pct" | cut -d. -f1)
        min=$(echo "$pct" | cut -d. -f2 | cut -c1)
        tenths=$((maj * 10 + ${min:-0}))
        sum=$((sum + tenths))
        cnt=$((cnt + 1))
    done

    avg_t=$((sum / cnt))
    whole=$((avg_t / 10))
    dec=$((avg_t % 10))
    echo "Average coverage across $cnt packages: ${whole}.${dec}%"
    echo "PASS (coverage only — no 80 % gate)"
    echo ""
    echo "=== Detailed function coverage ==="
    echo "   (only showing functions < 100%; from 'go tool cover -func')"
    echo ""
    for p in $PACKAGES; do
        output=$(go tool cover -func="coverage.${p}.out" 2>/dev/null)

        if echo "$output" | grep -q -v '100.0%'; then
            echo "===> Package: $p"
            echo "$output" | grep -v '100.0%'
        else
            echo "===> Package: $p COMPLETE"
        fi
    done
}

# --- gate: final block for `make test-cover` / ci / check (strict 80% + PASS/FAIL) ---
gate() {
    local sum=0 cnt=0 p pct maj min tenths avg_t whole dec

    for p in $PACKAGES; do
        pct=$(go tool cover -func="coverage.${p}.out" 2>/dev/null \
            | grep '^total:' \
            | grep -o '[0-9][0-9.]*%' \
            | tr -d '%' || true)
        [ -n "$pct" ] || pct=0
        maj=$(echo "$pct" | cut -d. -f1)
        min=$(echo "$pct" | cut -d. -f2 | cut -c1)
        tenths=$((maj * 10 + ${min:-0}))
        sum=$((sum + tenths))
        cnt=$((cnt + 1))
    done

    avg_t=$((sum / cnt))
    whole=$((avg_t / 10))
    dec=$((avg_t % 10))
    echo "Average coverage across $cnt packages: ${whole}.${dec}%"
    if [ "$whole" -lt 80 ]; then
        echo "FAIL: average coverage ${whole}.${dec}% < 80%"
        exit 1
    fi
    echo "PASS"
}

# --- main dispatcher ---
cmd="${1:-help}"
shift || true

case "$cmd" in
    build)            build "$@" ;;
    collect)          collect "$@" ;;
    collect-quiet)    collect_quiet "$@" ;;
    summarize)        summarize ;;
    gate)             gate ;;
    *)
        echo "scripts/coverage.sh: unknown command '$cmd'" >&2
        echo "valid: build PKG NAME | collect NAME | collect-quiet NAME | summarize | gate" >&2
        exit 1
        ;;
esac
