package main

import (
	"encoding/json"
	"fmt"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ws "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_ws"
)

func fixedPrivKey(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	key, _ := ec.PrivateKeyFromBytes(buf)
	return key
}

func main() {
	clientPriv := fixedPrivKey(0x10)
	serverPriv := fixedPrivKey(0x20)

	salt := "0a0b0c0d" // deterministic for test
	body, headers, err := ws.BuildHandshakeRequest(clientPriv, serverPriv.PubKey(), salt, "deadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := map[string]interface{}{
		"method":     "POST",
		"uriPath":    "/ws/handshake",
		"body":       body,
		"headers":    headers,
		"serverPriv": fmt.Sprintf("%x", serverPriv.Serialize()),
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
