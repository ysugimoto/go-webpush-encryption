package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	wp "github.com/ysugimoto/go-webpush-encryption"
	"io/ioutil"
	"math/big"
	"testing"
)

type serverKeyMap struct {
	X string `json:"x"`
	Y string `json:"y"`
	D string `json:"d"`
}

const expect = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsInN1YiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODg4OCIsImV4cCI6MTAwMDAwfQ.qW1lQYtHjKqus1K43dgGfQU_op0wjOYrwRwpeoxelp4tD8y9YiLuRxVpdTqSShqLpZuNt9Z6aTOrHr2z8ZZDWA"

func TestJWTSigner(t *testing.T) {
	buf, _ := ioutil.ReadFile(wp.SERVERKEY_PATH)

	km := serverKeyMap{}
	err := json.Unmarshal(buf, &km)
	if err != nil {
		panic(err)
	}

	pk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     toBigInt(km.X),
			Y:     toBigInt(km.Y),
		},
		D: toBigInt(km.D),
	}

	header := wp.NewJWTHeader()
	payload := wp.NewJWTClaim("https://fcm.googleapis.com", "http://localhost:8888", 100000)
	claim := payload.GenerateClaimString(header)
	token := claim.Sign(pk)

	if token != expect {
		t.Errorf("Expect: %s\nActual: %s\n", expect, token)
	}

}

func toBigInt(keyStr string) *big.Int {
	dec, _ := base64.StdEncoding.DecodeString(keyStr)
	bi := new(big.Int)
	bi.SetBytes(dec)

	return bi
}
