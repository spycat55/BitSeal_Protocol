//go:build !fulljwt

package bitsealws

import (
	"errors"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/golang-jwt/jwt/v5"
)

// CreateJWT stub returns empty string; compile-time placeholder.
func CreateJWT(_ jwt.MapClaims, _ *ec.PrivateKey, _ int64) (string, error) {
	return "", errors.New("CreateJWT not available in stub build")
}

// VerifyJWT stub always returns error.
func VerifyJWT(_ string, _ *ec.PublicKey) (jwt.MapClaims, error) {
	return nil, errors.New("VerifyJWT not available in stub build")
}
