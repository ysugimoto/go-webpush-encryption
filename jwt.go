package webpush

import (
	"encoding/json"
	"fmt"
	"time"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

type JWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

func NewJWTHeader() *JWTHeader {
	return &JWTHeader{
		Type:      "JWT",
		Algorithm: "ES256",
	}
}

type JWTClaim struct {
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	Expired  int64  `json:"exp"`
}

type JWTClaimString struct {
	claim string
}

func (s *JWTClaimString) String() string {
	return s.claim
}

func (s *JWTClaimString) Sign(pk *ecdsa.PrivateKey) string {
	hash := sha256.New()
	hash.Write([]byte(s.claim))

	R, S, err := ecdsa.Sign(rand.Reader, pk, hash.Sum(nil))
	if err != nil {
		panic(err)
	}

	curveBits := pk.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits&8 > 0 {
		keyBytes += 1
	}

	RB := R.Bytes()
	RBP := make([]byte, keyBytes)
	copy(RBP[keyBytes-len(RB):], RB)

	SB := S.Bytes()
	SBP := make([]byte, keyBytes)
	copy(SBP[keyBytes-len(SB):], SB)

	return fmt.Sprintf("%s.%s", s, urlSafeBase64Encode(append(RBP, SBP...)))
}

func NewJWTClaim(audience, subject string, expired int64) *JWTClaim {
	if expired == 0 {
		cur := time.Now().UnixNano() / int64(time.Millisecond)
		expired = cur + 12*60*60
	}

	return &JWTClaim{
		Audience: audience,
		Subject:  subject,
		Expired:  expired,
	}
}

func (c *JWTClaim) GenerateClaimString(header *JWTHeader) *JWTClaimString {
	jh, _ := json.Marshal(header)
	jc, _ := json.Marshal(c)

	return &JWTClaimString{
		claim: fmt.Sprintf("%s.%s", urlSafeBase64Encode(jh), urlSafeBase64Encode(jc)),
	}
}
