package bitsealws_test

import (
	"net/url"
	"testing"

	"net/http/httptest"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	ws "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_ws"
)

func fixedPriv(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	k, _ := ec.PrivateKeyFromBytes(buf)
	return k
}

// TestConnectBitSealWS verifies that ConnectBitSealWS completes the two-step handshake and BST2 session.
func TestConnectBitSealWS(t *testing.T) {
	serverPriv := fixedPriv(0x55)
	server := ws.NewServer(serverPriv)
	ts := httptest.NewServer(server)
	defer ts.Close()

	// Build ws URL from test server's HTTP address.
	httpURL, _ := url.Parse(ts.URL) // e.g. http://127.0.0.1:XXXXX
	wsURL := "ws://" + httpURL.Host + "/ws/socket"

	clientPriv := fixedPriv(0x33)

	conn, err := ws.ConnectBitSealWS(clientPriv, serverPriv.PubKey(), wsURL)
	if err != nil {
		t.Fatalf("ConnectBitSealWS failed: %v", err)
	}
	defer conn.Close()

	// Send & receive a short payload
	payload := []byte("ping")
	if err := conn.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	echo, err := conn.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", echo, payload)
	}
}
