package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	aesgcm "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
)

type record struct {
	Key    string `json:"key_hex"`
	Nonce  string `json:"nonce_hex"`
	Ad     string `json:"ad_hex"`
	Plain  string `json:"plain_hex"`
	Cipher string `json:"cipher_hex"`
	Tag    string `json:"tag_hex"`
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

func main() {
	key := randBytes(32)   // 256-bit key
	nonce := randBytes(12) // 96-bit nonce (IETF)
	ad := randBytes(9)     // same length as protocol AD
	plain := randBytes(32) // random 32-byte plaintext

	cipherOnly, tag, _ := aesgcm.AESGCMEncrypt(plain, key, nonce, ad)

	rec := record{
		Key:    hex.EncodeToString(key),
		Nonce:  hex.EncodeToString(nonce),
		Ad:     hex.EncodeToString(ad),
		Plain:  hex.EncodeToString(plain),
		Cipher: hex.EncodeToString(cipherOnly),
		Tag:    hex.EncodeToString(tag),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rec)
}
