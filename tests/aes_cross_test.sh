#!/usr/bin/env bash
set -euo pipefail

go run tests/go/aes_cross/gen.go > /tmp/aes_test.json
bun run tests/ts/aes_cross/ts_decode.ts /tmp/aes_test.json 