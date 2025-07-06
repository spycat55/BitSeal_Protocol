package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ws "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_ws"
)

type input struct {
	Method     string            `json:"method"`
	UriPath    string            `json:"uriPath"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
	ServerPriv string            `json:"serverPriv"`
}

func main() {
	data, _ := ioutil.ReadAll(os.Stdin)
	var in input
	json.Unmarshal(data, &in)
	// parse server private key to verify signature
	privBytes, _ := hexDecode(in.ServerPriv)
	serverPriv, _ := ec.PrivateKeyFromBytes(privBytes)

	_, salt, nonce, err := ws.VerifyHandshakeRequest(in.Body, in.Method, in.UriPath, in.Headers, serverPriv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify failed:", err)
		os.Exit(1)
	}
	fmt.Printf("verified salt=%s nonce=%s\n", salt, nonce)
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
