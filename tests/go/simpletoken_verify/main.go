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
	Token string `json:"token"`
	Pub   string `json:"pub"`
}

func main() {
	data, _ := ioutil.ReadAll(os.Stdin)
	var in input
	if err := json.Unmarshal(data, &in); err != nil {
		fmt.Fprintln(os.Stderr, "unmarshal:", err)
		os.Exit(1)
	}

	pubBytes, _ := hex.DecodeString(in.Pub)
	pub, err := ec.ParsePubKey(pubBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	claims, err := ws.VerifyToken(in.Token, pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify fail:", err)
		os.Exit(1)
	}
	fmt.Println("Go verify OK", claims)
}
