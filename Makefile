.PHONY: test cover build test-cover ci clean

test:
	go test -timeout=5s ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build:
	go build ./...

clean:
	@echo "=== clean: removing all artifacts, test binaries, coverage files, and Go caches ==="
	@# Remove common build outputs this project produces (root level)
	@rm -f blastradius blastradius.exe coverage*.out *.test 2>/dev/null || true
	@# Recursively remove stray test binaries (go test -c), built binaries, and any coverage profiles anywhere
	@find . -type f \( -name '*.test' -o -name 'blastradius' -o -name 'blastradius.exe' -o -name 'coverage*.out' \) -delete 2>/dev/null || true
	@# Thoroughly clear Go's build and test caches (clean target is allowed to be slow)
	@go clean -cache -testcache
	@# Remove common output directories + any legacy manual cache dir
	@rm -rf bin/ dist/ build/ out/ .gocache 2>/dev/null || true
	@# Best-effort clean of package artifacts
	@go clean ./... 2>/dev/null || true
	@echo "Clean complete."

# test-cover enforces the hard invariants for the *fast unit test suite*:
#
#   - Total wall-clock time of the entire `go test ./...` run must be ≤ 5 seconds.
#   - Statement coverage must be ≥ 80%.
#
# If either limit is violated, the target fails (non-zero exit).
#
# This is the target that should be used by CI and for local "is my change safe?"
# gating of the unit test surface.
#
# Slow integration / end-to-end tests (which are allowed to run longer and
# will naturally exercise daemon lifecycle, real sockets, timing windows, etc.)
# should live under a *separate* target and protocol (e.g. `make integration`
# or `make e2e`) with their own relaxed timing and coverage rules.
test-cover:
	@echo "=== test-cover: enforcing hard invariants (wall ≤5s AND coverage ≥80%) ==="
	@go clean -testcache
	@rm -f coverage.out 2>/dev/null || true
	@# Time the test run using only shell variables + date (no mktemp, no temp
	@# files, no TMP, no /usr/bin/time -o files). Live output from go test.
	@START=$$(date +%s.%N 2>/dev/null || date +%s); \
	if go test -count=1 -timeout=5s -coverprofile=coverage.out ./... 2>&1; then \
		END=$$(date +%s.%N 2>/dev/null || date +%s); \
		REAL=$$(awk "BEGIN { d=$$END - $$START; if (d<0) d+=86400; printf \"%.2f\", d }"); \
		echo "Wall-clock time: $${REAL}s"; \
		if awk "BEGIN { if ($$REAL > 5.0) exit 0; else exit 1 }"; then \
			echo "FAIL: Test suite took $${REAL}s (exceeds 5s hard limit)"; \
			exit 1; \
		fi; \
		COV=$$(go tool cover -func=coverage.out | grep '^total:' | awk '{print $$3}' | tr -d '%'); \
		echo "Coverage: $${COV}%"; \
		if awk "BEGIN { if ($$COV < 80) exit 0; else exit 1 }"; then \
			echo "FAIL: Coverage $${COV}% is below the 80% minimum"; \
			exit 1; \
		fi; \
		echo "✅ PASS: $${REAL}s wall time, $${COV}% coverage"; \
	else \
		echo "FAIL: 'go test' command failed (see output above)"; \
		exit 1; \
	fi

ci: test-cover
# Placeholder for future slow integration / end-to-end tests.
# These are intentionally allowed to exceed 5s and have different coverage expectations.
# integration:
#	go test -tags=integration -timeout=120s ./...