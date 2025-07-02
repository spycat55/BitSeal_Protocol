#!/usr/bin/env bash
# BitSeal-RTC Cross-Language Integration Test
# -------------------------------------------
# 1. Go 端握手 → TS 端校验
# 2. TS 端握手 → Go 端校验
# 任一步失败即返回非零

set -euo pipefail

GREEN="\033[0;32m"
NC="\033[0m"

echo -e "${GREEN}Step 0: Go unit tests …${NC}"
go test ./gocode/bitseal_rtc -v

echo -e "${GREEN}Step 0b: TS unit tests …${NC}"
bun test tscode/bitseal_rtc

# ───────────────────────────────────────
# Go → TS
# ───────────────────────────────────────

echo -e "${GREEN}Step 1: Go RTC handshake …${NC}"
go run ./tests/go/rtc_cross/go_rtc_sign.go > go_rtc.json

echo -e "${GREEN}Step 2: TS RTC verify …${NC}"
bun run tests/ts/rtc_cross/ts_rtc_verify.ts go_rtc.json

# ───────────────────────────────────────
# TS → Go
# ───────────────────────────────────────

echo -e "${GREEN}Step 3: TS RTC handshake …${NC}"
bun run tests/ts/rtc_cross/ts_rtc_sign.ts ts_rtc.json

echo -e "${GREEN}Step 4: Go RTC verify …${NC}"
go run ./tests/go/rtc_cross_verify/go_rtc_verify.go ts_rtc.json

# ───────────────────────────────────────
# Fragmentation (乱序 + 重复) Cross Test
# ───────────────────────────────────────

echo -e "${GREEN}Step 5: Cross-fragment test (disorder & dup) …${NC}"
./tests/cross_frag_test.sh

echo -e "${GREEN}All BitSeal-RTC cross tests passed successfully 🎉${NC}" 