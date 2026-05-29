.PHONY: test cover build test-cover ci

test:
	go test -timeout=5s ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build:
	go build ./...

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
	@rm -f coverage.out
	@TESTOUT=$$(mktemp); \
	TIMEFILE=$$(mktemp); \
	if /usr/bin/time -p -o "$$TIMEFILE" go test -count=1 -timeout=5s -coverprofile=coverage.out ./... 2>&1 | tee "$$TESTOUT"; then \
		REAL=$$(awk '/^real/ {print $$2}' "$$TIMEFILE" || echo 999); \
		echo "Wall-clock time: $${REAL}s"; \
		if awk "BEGIN { if ($$REAL > 5.0) exit 0; else exit 1 }"; then \
			echo "FAIL: Test suite took $${REAL}s (exceeds 5s hard limit)"; \
			rm -f "$$TIMEFILE" "$$TESTOUT"; exit 1; \
		fi; \
		COV=$$(go tool cover -func=coverage.out | grep '^total:' | awk '{print $$3}' | tr -d '%'); \
		echo "Coverage: $${COV}%"; \
		if awk "BEGIN { if ($$COV < 80) exit 0; else exit 1 }"; then \
			echo "FAIL: Coverage $${COV}% is below the 80% minimum"; \
			rm -f "$$TIMEFILE" "$$TESTOUT"; exit 1; \
		fi; \
		echo "✅ PASS: $${REAL}s wall time, $${COV}% coverage"; \
		rm -f "$$TIMEFILE" "$$TESTOUT"; \
	else \
		echo "FAIL: 'go test' command failed"; \
		cat "$$TESTOUT"; \
		rm -f "$$TIMEFILE" "$$TESTOUT"; \
		exit 1; \
	fi

ci: test-cover

# Placeholder for future slow integration / end-to-end tests.
# These are intentionally allowed to exceed 5s and have different coverage expectations.
# integration:
#	go test -tags=integration -timeout=120s ./...