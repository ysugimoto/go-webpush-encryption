package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"

	"strings"
)

func importUserPublicKey(curve elliptic.Curve, pubKey string) (ecdsa.PublicKey, error) {
	dec, err := urlSafeBase64Decode(pubKey)
	if err != nil {
		return nil, err
	}

	X, Y := elliptic.Unmarshal(curve, dec)
	return elliptic.PublicKey{
		X: X,
		Y: Y,
	}, nil
}

func urlSafeBase64Decode(input string) ([]byte, error) {
	input = strings.Replace("_", "+", -1).
		Replace("-", "/", -1).
		Replace(".", "=", -1)

	return base64.StdEncoding.DecodeString(input)
}
