#!/usr/bin/env bash
# BitSeal-WS Cross-Language Integration Test
# -----------------------------------------
# 1. Go 生成 WS 握手 → TS 校验
# 2. TS 生成 WS 握手 → Go 校验
# 任何一步失败即退出非零

set -euo pipefail

GREEN="\033[0;32m"
NC="\033[0m"

# ───────────────────────────────────────
# Go → TS
# ───────────────────────────────────────

echo -e "${GREEN}Step 1: Go WS handshake signing …${NC}"
go run ./tests/go/ws_cross_sign/main.go > ws_go_ws.json

echo -e "${GREEN}Step 2: TS side verifying …${NC}"
bun run tests/ts/ws/ws_verify.ts ws_go_ws.json

# ───────────────────────────────────────
# TS → Go
# ───────────────────────────────────────

echo -e "${GREEN}Step 3: TS WS handshake signing …${NC}"
bun run tests/ts/ws/ws_sign.ts ws_ts_ws.json

echo -e "${GREEN}Step 4: Go side verifying …${NC}"
cat ws_ts_ws.json | go run ./tests/go/ws_cross_verify/main.go

echo -e "${GREEN}All BitSeal-WS cross tests passed successfully 🎉${NC}" 