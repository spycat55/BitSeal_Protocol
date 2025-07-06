package bitsealws

import (
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func fixedPriv(b byte) *ec.PrivateKey {
	buf := make([]byte, 32)
	buf[31] = b
	k, _ := ec.PrivateKeyFromBytes(buf)
	return k
}

func TestSimpleTokenRoundtrip(t *testing.T) {
	priv := fixedPriv(3)
	pub := priv.PubKey()
	payload := map[string]any{"foo": "bar"}
	tok, err := CreateToken(payload, priv, 60)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyToken(tok, pub)
	if err != nil {
		t.Fatal(err)
	}
	if claims["foo"] != "bar" {
		b, _ := json.Marshal(claims)
		t.Fatalf("unexpected claims %s", string(b))
	}
}
