# BitSeal Protocol

BitSeal Protocol is a lightweight, end-to-end encryption layer and secure transport toolkit for peer-to-peer (P2P) applications.  It brings the "BitSeal" design philosophy to WebRTC, files, and blockchain use-cases, providing simple but strong cryptography without the overhead of certificates or pre-registration.

## Key Components

* **BitSeal-RTC** – Authenticated ECDH handshake (BSH1) and AEAD-encrypted transport (BST2) over WebRTC `DataChannel`, featuring 64-bit replay protection and optional 64 MiB message fragmentation.
* **Go SDK (`gocode/…`)** – Native implementation for servers, CLIs, and desktop apps.
* **TypeScript SDK (`tscode/…`)** – Runs in browsers, Deno, Bun, and Node.js.
* **Cross-tests** – Shared test-vectors to guarantee wire-level compatibility between the Go and TS stacks.

## Quick Demo (Terminal-to-Terminal Chat)

Prerequisites: **Go ≥1.22** and **Node.js ≥18**.

```bash
# Terminal A – offer side
cd gocode
go run ./tests/go/webrtc_chat/go_offer.go
```

```bash
# Terminal B – answer side
cd tscode
npx tsx tests/ts/webrtc_chat/ts_answer.ts
```

Follow the prompts to copy-paste the SDP between the two terminals – once connected, any text you type will be end-to-end encrypted via BitSeal-RTC.

## Repository Layout (simplified)

```
/BitSeal_Protocol        – Protocol specs & design notes
/gocode                  – Go implementation & examples
/tscode                  – TypeScript implementation & examples
/tests                   – Cross-language test-suite
```

## License

This project is released under the terms of the MIT License (see `LICENSE`).  Contributions and issue reports are welcome – feel free to open a PR!
