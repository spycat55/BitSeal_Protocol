package main

import (
	"encoding/json"
	"fmt"
	"os"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ws "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_ws"
)

func fixedPriv(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	k, _ := ec.PrivateKeyFromBytes(buf)
	return k
}

func main() {
	outPath := "token_go.json"
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	}

	priv := fixedPriv(0x33)
	pub := priv.PubKey()
	payload := map[string]any{"hello": "world"}
	tok, err := ws.CreateToken(payload, priv, 300)
	if err != nil {
		panic(err)
	}

	obj := map[string]any{
		"token": tok,
		"pub":   fmt.Sprintf("%x", pub.Compressed()),
	}
	f, err := os.Create(outPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(obj)
	fmt.Println("wrote", outPath)
}
