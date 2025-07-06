#!/usr/bin/env bash
# SimpleToken Cross-Language Integration Test
# 0. 语言自测（Go / TS）
# 1. Go 生成 Token -> TS 验证
# 2. TS 生成 Token -> Go 验证

set -euo pipefail
GREEN="\033[0;32m"
NC="\033[0m"

# ───────── 自测 ─────────

echo -e "${GREEN}Step 0a: Go unit test …${NC}"
(cd gocode && go test ./bitseal_ws -run TestSimpleTokenRoundtrip)

echo -e "${GREEN}Step 0b: TS unit test …${NC}"
(cd tscode && npx vitest run bitseal_ws/SimpleToken.test.ts)

# ───────── Go → TS ─────────

echo -e "${GREEN}Step 1: Go create token …${NC}"
go run ./tests/go/simpletoken_sign/main.go token_go.json

echo -e "${GREEN}Step 2: TS verify …${NC}"
bun run tests/ts/simpletoken/simpletoken_verify.ts token_go.json

# ───────── TS → Go ─────────

echo -e "${GREEN}Step 3: TS create token …${NC}"
bun run tests/ts/simpletoken/simpletoken_sign.ts token_ts.json

echo -e "${GREEN}Step 4: Go verify …${NC}"
cat token_ts.json | go run ./tests/go/simpletoken_verify/main.go

echo -e "${GREEN}All SimpleToken cross tests passed 🎉${NC}" 