# =============================================================================
# Blast Radius Makefile — the friendly developer entry point
# =============================================================================
#
# Run `make` (or `make help`) to see what you can do.
#
# New here? Start with `make help`. You almost never need to read past the "Public targets" section.

.DEFAULT_GOAL := help

# =============================================================================
# Coverage model
# ----------------------------------------------------
# A long-standing Go toolchain bug means `go test -cover ./...` produces
# untrustworthy numbers. We must collect **one package at a time**.
#
#   make cover        → per-package % + details (human)
#   make test-cover   → same + 80% gate + 5s execution-only limit (CI)
#
# THE UGLY PART IS 100% CONTAINED:
#   All build logic for coverage.*.test binaries + all collection, timing,
#   5s gate, .coverage-failed sentinel, averaging, and 80% decision live in:
#     scripts/coverage.sh
#
# It is called as a black box from the declarative targets below.
# If you are only adding a package or a normal target, you can completely
# ignore scripts/coverage.sh. The only thing you edit is the PACKAGES block.
#
# Everything else in this Makefile is ordinary targets, variables, and prerequisites.
#
# =============================================================================

# =============================================================================
# Parallelism for the coverage gate
# -----------------------------------------------------------------------------
# The <5s wall-time hard invariant for `make test-cover` / `make ci` / `make check`
# requires -j parallel execution of the per-package collectors. This tiny
# parse-time block forces it automatically for those goals so users never type -j.
# Everything else about timing, the 5s limit, the sentinel, abort, avg, and 80%
# gate lives in the single contained script (see below).
# =============================================================================
ifneq (,$(filter test-cover ci check,$(MAKECMDGOALS)))
MAKEFLAGS += -j4
endif

# -----------------------------------------------------------------------------
# Single source of truth: the packages we build, test, and cover
# -----------------------------------------------------------------------------
# PACKAGES + the PKG_* map are THE ONLY place package names/paths are listed.
# Everything else (cover-*, _quiet-cover-*, .PHONY, aggregation loops) is
# derived from this block via make functions or $(PACKAGES).
#
# When adding/removing/splitting a package: edit exactly these lines.
# -----------------------------------------------------------------------------

PACKAGES := cli cmd config daemon handlers detection discovery logging registry residue sources util

PKG_cli       := ./internal/cli
PKG_cmd       := ./cmd/blastradius
PKG_config    := ./internal/config
PKG_daemon    := ./internal/daemon
PKG_handlers  := ./internal/daemon/handlers
PKG_detection := ./internal/detection
PKG_discovery := ./internal/discovery
PKG_logging   := ./internal/logging
PKG_registry  := ./internal/registry
PKG_residue   := ./internal/residue
PKG_sources   := ./internal/sources
PKG_util      := ./internal/util

# -----------------------------------------------------------------------------
# Public targets (what humans and CI actually type)
# -----------------------------------------------------------------------------

## help: Print this message (also the default goal when you just type `make`)
help:
	@echo ""
	@echo "  \033[1mBlast Radius — development commands\033[0m"
	@echo ""
	@echo "  \033[36mmake test\033[0m          Run the entire test suite (fast, no coverage)"
	@echo "  \033[36mmake build\033[0m         Build the blastradius binary"
	@echo "  \033[36mmake cover\033[0m         Trustworthy per-package % + uncovered functions"
	@echo "  \033[36mmake cover-<pkg>\033[0m   Coverage for a single package (e.g. make cover-cli)"
	@echo "  \033[36mmake test-cover\033[0m    Strict gate: trustworthy numbers + 80% + wall-time (CI)"
	@echo "  \033[36mmake ci\033[0m            Alias for the strict gate (what CI should run)"
	@echo "  \033[36mmake clean\033[0m         Remove all artifacts, coverage files, test binaries, caches"
	@echo ""
	@echo "  \033[36mmake fmt\033[0m           Check formatting (fails if dirty)"
	@echo "  \033[36mmake fmt-fix\033[0m       Fixes formatting"
	@echo "  \033[36mmake vet\033[0m           Run go vet"
	@echo "  \033[36mmake tidy\033[0m          Run go mod tidy"
	@echo "  \033[36mmake loc\033[0m           Lines of code (prod only; files/lines/funcs/stmts per package)"
	@echo "  \033[36mmake check\033[0m         Local safety gate (test + vet + fmt + test-cover)"
	@echo "  \033[36mmake check-fix\033[0m     Check but with fmt-fix"
	@echo ""

## test: Run the entire test suite (fast, no coverage, 5 s suite timeout)
test:
	go test -timeout=5s ./...

## build: Build the blastradius binary into the current directory
build:
	go build -o blastradius ./cmd/blastradius

# -----------------------------------------------------------------------------
# Coverage test binaries (declarative — single way to produce them)
# -----------------------------------------------------------------------------
# Both `make cover*` and the gate depend on these. The build logic (and all
# the collection/timing/gate logic) lives in the single contained script:
#   scripts/coverage.sh
# -----------------------------------------------------------------------------

## build-coverage-testbin: Build one coverage-instrumented test binary
##   make build-coverage-testbin PKG=./internal/cli NAME=cli
.PHONY: build-coverage-testbin
build-coverage-testbin:
	@scripts/coverage.sh build "$(PKG)" "$(NAME)"

## build-coverage-testbins: Build for every package (prereq for the gate)
.PHONY: build-coverage-testbins
build-coverage-testbins: $(addprefix build-coverage-testbin-,$(PACKAGES))

build-coverage-testbin-%:
	@scripts/coverage.sh build "$(PKG_$*)" "$*"

## clean: Remove every artifact we ever create (binaries, coverage files,
##        test binaries, and Go caches)
clean:
	@rm -f coverage*.out coverage*.log coverage*.test *.test \
		blastradius blastradius.exe .coverage-failed 2>/dev/null || true
	@find . -type f \
		\( -name '*.test' \
		-o -name 'blastradius' \
		-o -name 'blastradius.exe' \
		-o -name 'coverage*.out' \
		-o -name 'coverage*.log' \
		-o -name 'coverage*.test' \
		-o -name '.coverage-failed' \) \
		-delete 2>/dev/null || true
	@go clean -cache -testcache 2>/dev/null || true
	@rm -rf bin/ dist/ build/ 2>/dev/null || true

## cover: Trustworthy per-package coverage + detailed uncovered functions
cover: $(addprefix cover-,$(PACKAGES))
	@PACKAGES="$(PACKAGES)" scripts/coverage.sh summarize

## test-cover: Strict CI gate — trustworthy numbers + 80% avg + 5s wall-time
##             per package. Parallelism is forced automatically (do not pass -j).
test-cover: build-coverage-testbins $(addprefix _quiet-cover-,$(PACKAGES))
	@if ! echo "$(MAKEFLAGS)" | grep -qE '(-j|--jobs)'; then \
		echo ""; \
		echo "ERROR: test-cover requires parallel execution"; \
		echo "       (the <5s hard invariant cannot be met sequentially)."; \
		echo "       This Makefile tries to force it automatically, but it"; \
		echo "       appears not to have taken effect."; \
		echo "       Try:  make -j4 test-cover"; \
		echo ""; \
		exit 1; \
	fi
	@PACKAGES="$(PACKAGES)" scripts/coverage.sh gate

## ci: Alias for the strict gate (what continuous integration should invoke)
ci: test-cover

# -----------------------------------------------------------------------------
# Per-package coverage collectors (pattern rules)
# -----------------------------------------------------------------------------
# Each collector depends on its own build target so that even under -j
# the binary is guaranteed ready before we try to run it.
# All the difficult timing/gate/sentinel logic lives in the script.
cover-%: build-coverage-testbin-%
	@scripts/coverage.sh collect "$*"

_quiet-cover-%: build-coverage-testbin-%
	@scripts/coverage.sh collect-quiet "$*"

# -----------------------------------------------------------------------------
# Optional developer niceties (cheap + welcoming for day-to-day work)
# -----------------------------------------------------------------------------

## fmt: Check formatting + imports (fails if dirty). Requires goimports.
fmt:
	@command -v goimports >/dev/null 2>&1 || { \
		echo "goimports is not installed."; \
		echo "   Run:  go install golang.org/x/tools/cmd/goimports@latest"; \
		exit 1; \
	}
	@if [ -n "$$(goimports -l .)" ]; then \
		echo "Formatting/import issues found:"; \
		goimports -l .; \
		exit 1; \
	fi
	@echo "goimports clean"

## fmt-fix: Automatically fix formatting and imports. Requires goimports.
fmt-fix:
	@command -v goimports >/dev/null 2>&1 || { \
		echo "goimports is not installed."; \
		echo "   Run:  go install golang.org/x/tools/cmd/goimports@latest"; \
		exit 1; \
	}
	goimports -l -w .
	@echo "Formatting and imports fixed"

## vet: Run go vet over the whole module
vet:
	go vet ./...

## tidy: Run go mod tidy (review any changes to go.mod/go.sum yourself)
tidy:
	go mod tidy
	@echo "go mod tidy complete — check 'git diff go.mod go.sum' if you care"

## loc: Report production (non-test) lines of code.
##      Uses scripts/loc.sh (the single contained implementation, like coverage.sh).
##      Buckets follow the PACKAGES list exactly. Includes rough func + stmt counts.
##      Run before/after architectural simplification work to prove measurable reduction.
##
##      The report is also written to docs/loc.txt (via LOC_OUT). Keep docs/loc.txt
##      in git; after changes, `make loc` updates it so `git diff docs/loc.txt` (or
##      comparing the committed snapshot vs a prior commit's version) shows the
##      numeric LOC impact.
loc:
	@LOC_OUT=docs/loc.txt PACKAGES="$(PACKAGES)" scripts/loc.sh

## check: Local "am I safe to push?" gate (tests + vet + fmt + the full coverage gate)
check: test vet fmt test-cover
	@$(MAKE) loc
	@echo "All checks passed."

check-fix: fmt-fix
	@$(MAKE) check

.PHONY: help test build clean cover test-cover ci fmt fmt-fix vet tidy loc check
# The cover-* and build-coverage-testbin-* targets are provided by pattern
# rules (they are never literal files on disk). All the difficult coverage
# collection + gate logic is in scripts/coverage.sh.
