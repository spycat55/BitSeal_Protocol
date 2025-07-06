#!/usr/bin/env bash
# Master test runner – executes all unit tests and cross-language integration tests
# Usage: ./run_all_tests.sh
# Exits non-zero on first failure.
set -euo pipefail

GREEN="\033[0;32m"
NC="\033[0m"

step(){ echo -e "${GREEN}=== $* ===${NC}"; }

# ───────────────────────────────────────
# Unit tests
# ───────────────────────────────────────
step "Go unit tests"
(cd gocode && go test ./...)

step "TypeScript unit tests"
(cd tscode && npx vitest run)

# ───────────────────────────────────────
# Cross-language / integration scripts
# ───────────────────────────────────────
step "BitSeal HTTP cross tests"
bash tests/cross_test.sh

step "BitSeal-RTC cross tests"
bash tests/rtc_cross_test.sh

step "SimpleToken cross tests"
bash tests/simpletoken_cross_test.sh

step "BitSeal-WS cross tests"
bash tests/ws_cross_test.sh

step "ALL TESTS PASSED 🎉" 