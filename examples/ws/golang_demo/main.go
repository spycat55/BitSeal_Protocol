package main

import (
	"fmt"
	"log"
	"net/http"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	rtc "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_rtc"
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

	// 测试新版 OnMessage：收到消息后添加前缀回复
	srv.OnMessage = func(sess *rtc.Session, plain []byte) ([]byte, error) {
		log.Printf("[server onMessage] recv plain: %q", string(plain))
		resp := []byte("server ack: " + string(plain))
		return resp, nil
	}

	// 添加握手回调，向返回 JSON 注入测试字段
	srv.OnHandshakeResponse = func(r *http.Request, clientPub *ec.PublicKey, nonce string) map[string]any {
		return map[string]any{
			"role":    "guest",
			"welcome": "hello from Go server",
		}
	}

	addr := ":8080"
	fmt.Println("BitSeal-WS demo server listening on", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal(err)
	}
}
