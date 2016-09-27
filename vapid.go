package webpush

import (
	"encoding/json"
	"fmt"
	"time"

	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

type jwtHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type jwtBody struct {
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	Expired  int64  `json:"exp"`
}

type Vapid struct {
	privateKey *ecdsa.PrivateKey
}

func NewVapid(pk *ecdsa.PrivateKey) *Vapid {
	return &Vapid{
		privateKey: pk,
	}
}

func (v *Vapid) Token(audience, subject string, expired int64) string {
	if expired == 0 {
		cur := time.Now().UnixNano() / int64(time.Millisecond)
		expired = cur + 12*60*60
	}

	header, _ := json.Marshal(jwtHeader{Type: "JWT", Algorithm: "ES256"})
	body, _ := json.Marshal(jwtBody{Audience: audience, Subject: subject, Expired: expired})
	claim := fmt.Sprintf("%s.%s", urlSafeBase64Encode(header), urlSafeBase64Encode(body))

	hash := sha256.New()
	hash.Write([]byte(claim))

	R, S, err := ecdsa.Sign(rand.Reader, v.privateKey, hash.Sum(nil))
	if err != nil {
		panic(err)
	}

	RB := R.Bytes()
	RBP := make([]byte, 32)
	copy(RBP[32-len(RB):], RB)

	SB := S.Bytes()
	SBP := make([]byte, 32)
	copy(SBP[32-len(SB):], SB)

	return fmt.Sprintf("%s.%s", claim, urlSafeBase64Encode(append(RBP, SBP...)))
}
