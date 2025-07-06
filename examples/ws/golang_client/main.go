package main

import (
	"log"
	"time"

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
	clientPriv := fixedPriv(0x33)
	serverPub := fixedPriv(0x55).PubKey()

	conn, err := ws.ConnectBitSealWS(clientPriv, serverPub, "ws://localhost:8080/ws/socket")
	if err != nil {
		log.Fatal("connect failed:", err)
	}
	defer conn.Close()
	log.Println("[client] connected to BitSeal-WS server")
	log.Printf("[client] extra fields: %+v", conn.Extra)

	// 测试 Session.PeerPub()
	peer := conn.Session.PeerPub()
	log.Printf("[client] session.PeerPub = %x", peer.Compressed())
	if !peer.IsEqual(serverPub) {
		log.Fatalf("peer pub mismatch, expect %x", serverPub.Compressed())
	}
	log.Println("[client] peer pub verified OK")

	// 注册 OnMessage 回调，收到服务器消息时触发
	conn.OnMessage = func(_ *rtc.Session, plain []byte) ([]byte, error) {
		log.Printf("[client onMessage] recv: %q", string(plain))
		return nil, nil // 不再回复
	}
	conn.ServeAsync() // 开启后台读取循环

	msg := []byte("hello BitSeal-WS from Go client")
	if err := conn.Write(msg); err != nil {
		log.Fatal("write error:", err)
	}
	log.Printf("[client] send: %q", msg)

	time.Sleep(500 * time.Millisecond)
	log.Println("[client] done, closing")
}
