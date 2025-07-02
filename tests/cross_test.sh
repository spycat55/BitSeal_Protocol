#!/usr/bin/env bash
# BitSeal Cross-Language Integration Test
# --------------------------------------
# 1. Go 生成签名 → TS 验证
# 2. TS 生成签名 → Go 验证
# 3. BitSeal-RTC
# 任何一步失败即退出非零

set -euo pipefail

GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"

# ───────────────────────────────────────
# Go → TS
# ───────────────────────────────────────

echo -e "${GREEN}Step 1: Go client signing …${NC}"
go run ./tests/go/cross_sign > go_sign.json
echo -e "${GREEN}Step 2: TS server verifying …${NC}"
npx tsx tests/ts/cross/ts_verify.ts go_sign.json

# ───────────────────────────────────────
# TS → Go
# ───────────────────────────────────────

echo -e "${GREEN}Step 3: TS client signing …${NC}"
npx tsx tests/ts/cross/ts_sign.ts ts_sign.json
echo -e "${GREEN}Step 4: Go server verifying …${NC}"
go run ./tests/go/cross_verify ts_sign.json

echo -e "${GREEN}All BitSeal HTTP cross tests passed successfully 🎉${NC}" 