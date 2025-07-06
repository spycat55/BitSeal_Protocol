package main

import (
	"log"
	"time"

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
	clientPriv := fixedPriv(0x33)
	serverPub := fixedPriv(0x55).PubKey()

	conn, err := ws.ConnectBitSealWS(clientPriv, serverPub, "ws://localhost:8080/ws/socket")
	if err != nil {
		log.Fatal("connect failed:", err)
	}
	defer conn.Close()
	log.Println("[client] connected to BitSeal-WS server")

	msg := []byte("hello BitSeal-WS from Go client")
	if err := conn.Write(msg); err != nil {
		log.Fatal("write error:", err)
	}
	log.Printf("[client] send: %q\n", msg)

	echo, err := conn.Read()
	if err != nil {
		log.Fatal("read error:", err)
	}
	log.Printf("[client] recv: %q\n", echo)

	time.Sleep(200 * time.Millisecond)
	log.Println("[client] done, closing")
}
