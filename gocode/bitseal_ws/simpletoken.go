package bitsealws

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// CreateToken builds payload JSON, adds iat/exp, signs SHA256(payload) with secp256k1 ECDSA.
// Returns base64url(payload) + "." + base64url(signatureDER)
func CreateToken(payload map[string]any, priv *ec.PrivateKey, expSec int64) (string, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	now := time.Now().Unix()
	payload["iat"] = now
	if expSec > 0 {
		payload["exp"] = now + expSec
	}
	jsonBytes, _ := json.Marshal(payload)
	payloadEnc := base64.RawURLEncoding.EncodeToString(jsonBytes)

	digest := crypto.Sha256(jsonBytes)

	// construct ecdsa private key
	curve := ec.S256()
	d := new(big.Int).SetBytes(priv.Serialize())
	pkX, pkY := curve.ScalarBaseMult(d.Bytes())
	ecdsaPriv := ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: pkX, Y: pkY}, D: d}

	r, s, err := ecdsa.Sign(rand.Reader, &ecdsaPriv, digest)
	if err != nil {
		return "", err
	}
	// enforce low-s
	N := curve.Params().N
	halfN := new(big.Int).Rsh(N, 1)
	if s.Cmp(halfN) == 1 {
		s.Sub(N, s)
	}
	derBytes, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	sigEnc := base64.RawURLEncoding.EncodeToString(derBytes)
	return payloadEnc + "." + sigEnc, nil
}

// VerifyToken parses token, verifies signature, returns payload claims.
func VerifyToken(token string, pub *ec.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("token parts")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		return nil, err
	}

	digest := crypto.Sha256(payloadBytes)

	// convert pub to ecdsa.PublicKey
	curve := ec.S256()
	point, err := ec.ParsePubKey(pub.Compressed())
	if err != nil {
		return nil, err
	}
	ecdsaPub := ecdsa.PublicKey{Curve: curve, X: point.X, Y: point.Y}
	ok := ecdsa.Verify(&ecdsaPub, digest, sig.R, sig.S)
	if !ok {
		return nil, errors.New("sig invalid")
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, errors.New("token expired")
		}
	}
	return claims, nil
}
