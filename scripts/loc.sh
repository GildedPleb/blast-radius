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
PACKAGES="${PACKAGES:-cli cmd config daemon handlers detection discovery logging registry residue sources util}"

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

print_loc_report() {
  echo "=== Blast Radius LOC (production *.go only; all _test.go excluded) ==="
  echo ""

  # --- Per-package buckets (using PACKAGES list, same as cover) ---
  printf "  %-12s %6s %8s %6s %7s\n" "PACKAGE" "FILES" "LINES" "FUNCS" "STMTS"
  echo "  ----------------------------------------------------"

  total_files=0
  total_lines=0
  total_funcs=0
  total_stmts=0

  for p in $PACKAGES; do
    dir=$(pkg_dir "$p")
    if [ ! -d "$dir" ]; then
      printf "  %-12s %6s %8s %6s %7s\n" "$p" "0" "0" "0" "0"
      continue
    fi

    read fcnt lcnt gcnt scnt <<<"$(compute_counts "$dir")"

    printf "  %-12s %6s %8s %6s %7s\n" "$p" "$fcnt" "$lcnt" "$gcnt" "$scnt"

    total_files=$((total_files + fcnt))
    total_lines=$((total_lines + lcnt))
    total_funcs=$((total_funcs + gcnt))
    total_stmts=$((total_stmts + scnt))
  done

  echo "  ----------------------------------------------------"
  printf "  %-12s %6s %8s %6s %7s\n" "TOTAL" "$total_files" "$total_lines" "$total_funcs" "$total_stmts"
  echo ""
  # To capture the authoritative total for before/after or tickets:
  #   make loc | grep -E '  TOTAL'
}

# Support for committed LOC snapshots:
#   LOC_OUT=docs/loc.txt make loc
# writes the exact report to the file (while still printing it via tee).
# This lets you keep docs/loc.txt in git. After code changes that affect
# architecture/LOC, run `make loc`; the updated docs/loc.txt in your tree
# can then be diffed against the version from the previous commit to see
# numeric impact ("prove measurable reduction").
if [ -n "${LOC_OUT:-}" ]; then
  print_loc_report | tee "$LOC_OUT"
else
  print_loc_report
fi
