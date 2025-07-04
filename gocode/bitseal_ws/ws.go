package bitsealws

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	bsweb "bitseal/gocode/bitseal_web"
	rtc "bitseal/gocode/bitseal_rtc"

	"github.com/golang-jwt/jwt/v5"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"encoding/hex"
	"strings"
	"encoding/json"
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
	body = fmt.Sprintf("{\"proto\":\"BitSeal-WS/1.0\",\"pk\":\"%s\",\"salt\":\"%s\",\"nonce\":\"%s\"}",
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

// CreateJWT returns ES256K token signed by serverPriv
func CreateJWT(claims jwt.MapClaims, serverPriv *ec.PrivateKey, expSec int64) (string, error) {
	if claims == nil {
		claims = jwt.MapClaims{}
	}
	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Duration(expSec) * time.Second).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256K, claims)
	ecdsaKey := (*ecdsa.PrivateKey)(serverPriv.ToECDSA())
	return token.SignedString(ecdsaKey)
}

// VerifyJWT verifies token with server public key
func VerifyJWT(tokenStr string, serverPub *ec.PublicKey) (jwt.MapClaims, error) {
	ecdsaPub := (*ecdsa.PublicKey)(serverPub.ToECDSA())
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) { return ecdsaPub, nil })
	return claims, err
}

// NewSessionFromJWT builds BST2 session using jwt payload salts
func NewSessionFromJWT(selfPriv *ec.PrivateKey, serverPub *ec.PublicKey, selfSaltHex string, jwtPayload jwt.MapClaims) (*rtc.Session, error) {
	saltS, ok := jwtPayload["salt_s"].(string)
	if !ok {
		return nil, errors.New("salt_s missing")
	}
	selfSalt, _ := hex.DecodeString(selfSaltHex)
	peerSalt, _ := hex.DecodeString(saltS)
	return rtc.NewSession(selfPriv, serverPub, selfSalt, peerSalt)
} 