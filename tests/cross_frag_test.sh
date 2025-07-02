#!/usr/bin/env bash
# Cross-language fragment test (Go ↔ TS)
set -euo pipefail

GREEN="\033[0;32m"
NC="\033[0m"

printf "${GREEN}1. Go dump frames ...${NC}\n"
go run ./tests/go/rtc_cross_frag_dump/go_dump.go frames_go.json

printf "${GREEN}2. TS verify & re-encode ...${NC}\n"
bun run tests/ts/rtc_cross/ts_check.ts frames_go.json frames_ts.json

printf "${GREEN}3. Go verify TS frames ...${NC}\n"
go run ./tests/go/rtc_cross_frag_verify/go_verify.go frames_ts.json

printf "${GREEN}Cross-fragment test passed 🎉${NC}\n" 