#!/usr/bin/env bash
#
# scripts/loc.sh
#
# Lines of code measurement (production code only; tests excluded).
# Mirrors the "contained ugly" model of scripts/coverage.sh:
#   - All measurement + per-package bucketing + formatting lives here.
#   - The only thing callers edit is the PACKAGES + PKG_* block in the Makefile.
#
# Usage (from Makefile):
#   PACKAGES="cli cmd ..." scripts/loc.sh
#
# Output is a per-package breakdown (files/lines/funcs/stmts) aligned to the
# PACKAGES list in the Makefile, plus a TOTAL row. This is the single source
# of truth for "make loc" before/after deltas on the architecture.
# (See comments inside print_loc_report for why we no longer emit a separate
# top-level totals block.)
#
# "statements" is a cheap static approximation (count of common statement
# introducers across non-test .go). For precise executed stmt counts use
# the existing `make cover` (go tool cover -func). We keep loc fast and
# tool-free like fmt/vet/tidy.
# =============================================================================

set -euo pipefail

# PACKAGES comes from the Makefile (single source of truth).
# If not provided, fall back to a reasonable default (for direct runs).
PACKAGES="${PACKAGES:-cli cmd config daemon handlers detection discovery logging policy registry residue scrub sources util}"

# Baseline for per-package and total deltas. We prefer `git show HEAD:docs/loc.txt`
# (the previously committed snapshot) so deltas always reflect "current state vs.
# what was committed before this run". This supports the in-line delta display.
baseline_text=""
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  baseline_text=$(git show HEAD:docs/loc.txt 2>/dev/null || true)
fi
if [ -z "$baseline_text" ]; then
  baseline_text=$(cat docs/loc.txt 2>/dev/null || true)
fi

# Map package short name -> filesystem dir (must stay in sync with Makefile PKG_*).
pkg_dir() {
  case "$1" in
    cmd)      echo "./cmd/blastradius" ;;
    handlers) echo "./internal/daemon/handlers" ;;
    *)        echo "./internal/$1" ;;
  esac
}

# All counts below are deliberately scoped to the PACKAGES list defined in the
# Makefile (the single source of truth for the architecture we are measuring
# and simplifying). This is what "make loc" and the committed docs/loc.txt
# track for before/after deltas.
#
# We used to also print a full-tree grand total at the top. That was removed
# because (a) it no longer differed from the table TOTAL once we fixed scoping
# bugs, and (b) having two different measurements in the same report caused
# confusion for future readers. If you ever need a true "everything in the
# repo" number, run the find yourself or extend the script.
#
# Rough static "statements": count of lines that look like they start a statement
# (if/for/return/go/defer/switch/select/case/break/continue/fallthrough/ + assignments/decls).
# This is intentionally a cheap proxy; not a full AST count.

compute_counts() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    echo "0 0 0 0"
    return
  fi

  # Use -maxdepth 1 so that e.g. "daemon" does not recursively count the
  # sibling "handlers" package (which is a separate entry in PACKAGES).
  local pkg_go
  pkg_go=$(find "$dir" -maxdepth 1 -name '*.go' ! -name '*_test.go' | sort)

  local fcnt lcnt gcnt scnt
  # Guard against empty input: plain `echo "" | wc -l` yields 1.
  if [ -z "$pkg_go" ]; then
    fcnt=0
  else
    fcnt=$(echo "$pkg_go" | grep -c .)
  fi
  lcnt=$(echo "$pkg_go" | xargs cat 2>/dev/null | wc -l | tr -d ' ' || echo 0)
  gcnt=$(echo "$pkg_go" | xargs grep -l '^func ' 2>/dev/null | xargs grep '^func ' 2>/dev/null | wc -l | tr -d ' ' || echo 0)
  scnt=$(echo "$pkg_go" | xargs cat 2>/dev/null \
    | grep -E '^\s*(if |for |return|go |defer |switch |select |case |break|continue|fallthrough|var |const |[A-Za-z_][A-Za-z0-9_]*\s*(:=|:=| = | \+= | -= ))' \
    | wc -l | tr -d ' ' || echo 0)

  echo "$fcnt $lcnt $gcnt $scnt"
}

# get_prev_nums extracts the four numbers (files lines funcs stmts) for a given
# package name (or "TOTAL") from the baseline_text. Uses awk on $1 match because
# data rows have pkgname as first field after whitespace split.
get_prev_nums() {
  local p="$1"
  local text="$2"
  if [ -z "$text" ]; then
    echo "0 0 0 0"
    return
  fi

  echo "$text" | awk -v pkg="$p" '
    $1 == pkg {
      # New format only: current values are fields 3, 7, 11, 15
      print $3, $7, $11, $15
      exit
    }
  ' || echo "0 0 0 0"
}

# Helper with cleaner formatting and better alignment
format_metric() {
  local current=$1
  local prev=$2

  if [ -z "$prev" ] || [ "$prev" -eq 0 ]; then
    printf "%5s      0    0.00%%" "$current"
    return
  fi

  local delta=$((current - prev))
  local pct
  pct=$(awk -v d="$delta" -v p="$prev" 'BEGIN { printf "%.2f", (d * 100.0 / p) }' 2>/dev/null || echo "0.00")

  local delta_str
  local pct_str

  if [ "$delta" -gt 0 ]; then
    delta_str=$(printf "+%d" "$delta")
    pct_str=$(printf -- "+%.2f%%" "$pct")
  elif [ "$delta" -lt 0 ]; then
    delta_str=$(printf "%d" "$delta")
    pct_str=$(printf -- "-%.2f%%" "${pct#-}")
  else
    delta_str=" 0"
    pct_str="0.00%"
  fi

  printf "%5s  %5s  %8s" "$current" "$delta_str" "$pct_str"
}

print_loc_report() {
  echo "=== Blast Radius LOC (production *.go only; all _test.go excluded) ==="
  echo ""

  printf "  %-12s  %-23s  %-23s  %-23s  %-23s\n" \
    "PACKAGE" "FILES" "LINES" "FUNCS" "STMTS"

  echo "  -------------------------------------------------------------------------------------------------------------"

  total_files=0 total_lines=0 total_funcs=0 total_stmts=0
  total_pf=0 total_pl=0 total_pg=0 total_ps=0

  for p in $PACKAGES; do
    dir=$(pkg_dir "$p")
    if [ ! -d "$dir" ]; then
      printf "  %-11s | %-21s | %-22s | %-21s | %-21s\n" "$p" "0" "0" "0" "0"
      continue
    fi

    read fcnt lcnt gcnt scnt <<<"$(compute_counts "$dir")"

    if [ -n "$baseline_text" ]; then
      prev_nums=$(get_prev_nums "$p" "$baseline_text")
      read pf pl pg ps <<< "$prev_nums"

      f_str=$(format_metric "$fcnt" "$pf")
      l_str=$(format_metric "$lcnt" "$pl")
      g_str=$(format_metric "$gcnt" "$pg")
      s_str=$(format_metric "$scnt" "$ps")

      total_pf=$((total_pf + pf))
      total_pl=$((total_pl + pl))
      total_pg=$((total_pg + pg))
      total_ps=$((total_ps + ps))
    else
      f_str=$(format_metric "$fcnt" "")
      l_str=$(format_metric "$lcnt" "")
      g_str=$(format_metric "$gcnt" "")
      s_str=$(format_metric "$scnt" "")
    fi

    printf "  %-11s | %s | %s | %s | %s\n" "$p" "$f_str" "$l_str" "$g_str" "$s_str"

    total_files=$((total_files + fcnt))
    total_lines=$((total_lines + lcnt))
    total_funcs=$((total_funcs + gcnt))
    total_stmts=$((total_stmts + scnt))
  done

  echo "  -------------------------------------------------------------------------------------------------------------"

  if [ -n "$baseline_text" ]; then
    tf=$(format_metric "$total_files" "$total_pf")
    tl=$(format_metric "$total_lines" "$total_pl")
    tg=$(format_metric "$total_funcs" "$total_pg")
    ts=$(format_metric "$total_stmts" "$total_ps")
  else
    tf=$(format_metric "$total_files" "")
    tl=$(format_metric "$total_lines" "")
    tg=$(format_metric "$total_funcs" "")
    ts=$(format_metric "$total_stmts" "")
  fi

  printf "  %-11s | %s | %s | %s | %s\n" "TOTAL" "$tf" "$tl" "$tg" "$ts"
}

# Support for committed LOC snapshots + inline deltas:
#   LOC_OUT=docs/loc.txt make loc
# writes the report (table + TOTAL + *inline per-package and TOTAL deltas*)
# to the file via tee. The file is kept in git as the new baseline snapshot.
#
# Deltas are shown *granularly inline* under the LINES column.
# CRITICAL FOR DIFFS: EVERY package row + TOTAL ALWAYS gets exactly two
# sub-lines (even for 0 delta), and each is padded to full 45-char row width
# with trailing spaces. This keeps block structure (3 lines per pkg) so
# `git diff docs/loc.txt` doesn't get misaligned.
#
# Baseline from `git show HEAD:docs/loc.txt`. Current numbers use today's
# PACKAGES. After changes, `make loc` writes the enhanced report (with
# always-present padded sub-lines) to the file.
#
# After code changes, `make loc` (or `make check`) updates the snapshot and
# shows the deltas inline for the story/PR.
if [ -n "${LOC_OUT:-}" ]; then
  print_loc_report | tee "$LOC_OUT"
else
  print_loc_report
fi

# (No separate delta section anymore: deltas are now shown inline in the table
# above for better per-package targeting, as requested.)
