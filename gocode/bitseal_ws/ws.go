package bitsealws

import (
	"errors"
	"fmt"

	bsweb "github.com/spycat55/BitSeal_Protocol/gocode/bitseal_web"

	"encoding/hex"
	"encoding/json"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// BuildHandshakeRequest constructs body+headers like TS side.
func BuildHandshakeRequest(clientPriv *ec.PrivateKey, serverPub *ec.PublicKey, salt string, nonce string) (body string, headers map[string]string, err error) {
	if salt == "" {
		return "", nil, errors.New("salt required")
	}
	if nonce == "" {
		n, _ := bsweb.RandomNonce()
		nonce = n
	}
	body = fmt.Sprintf("{\"proto\":\"BitSeal-WS.1\",\"pk\":\"%s\",\"salt\":\"%s\",\"nonce\":\"%s\"}",
		fmt.Sprintf("%x", clientPriv.PubKey().Compressed()), salt, nonce)
	headers, err = bsweb.SignRequest("POST", "/ws/handshake", "", body, clientPriv, serverPub)
	return
}

// VerifyHandshakeRequest validates and returns client pubkey & salt
func VerifyHandshakeRequest(body, method, uriPath string, headers map[string]string, serverPriv *ec.PrivateKey) (*ec.PublicKey, string, string, error) {
	ok, err := bsweb.VerifyRequest(method, uriPath, "", body, headers, serverPriv)
	if err != nil || !ok {
		return nil, "", "", errors.New("verify failed")
	}
	var obj struct {
		Proto string `json:"proto"`
		PK    string `json:"pk"`
		Salt  string `json:"salt"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return nil, "", "", err
	}
	pkBytes, err := hex.DecodeString(obj.PK)
	if err != nil {
		return nil, "", "", err
	}
	peerPub, err := ec.ParsePubKey(pkBytes)
	return peerPub, obj.Salt, obj.Nonce, err
}

// （已移除旧 JWT 相关辅助函数）
