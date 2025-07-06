package main

import (
	"fmt"
	"log"
	"net/http"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ws "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_ws"
)

func fixedPriv(val byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = val
	k, _ := ec.PrivateKeyFromBytes(buf)
	return k
}

func main() {
	serverPriv := fixedPriv(0x55)
	srv := ws.NewServer(serverPriv)

	addr := ":8080"
	fmt.Println("BitSeal-WS demo server listening on", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal(err)
	}
}
