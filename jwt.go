package webpush

import (
	"encoding/json"
	"fmt"
	"time"
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

func generateJWTClaimString(header *JWTHeader, claim *JWTClaim) string {
	jh, _ := json.Marshal(header)
	jc, _ := json.Marshal(claim)

	return fmt.Sprintf(
		"%s.%s",
		urlSafeBase64Encode(jh),
		urlSafeBase64Encode(jc),
	)
}
