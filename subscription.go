package webpush

import (
	"strings"
)

type PushSubscription struct {
	Keys     PushSubscriptionKey `json:"keys"`
	Payload  string              `json:"payload"`
	Version  int                 `json:"int"`
	Endpoint string              `json:"endpoint"`
	JWT      *JWTClaim           `json:"jwt"`
}

type PushSubscriptionKey struct {
	P256DH string `json:"p256dh"`
	Auth   string `json:"auth"`
}

func (p PushSubscription) hasAuth() (has bool) {
	if p.Keys.Auth != "" {
		has = true
	}

	return
}

func (p PushSubscription) hasPayload() (has bool) {
	if p.Keys.P256DH != "" && p.Payload != "" {
		has = true
	}

	return
}

func (p PushSubscription) isGCM() (is bool) {
	if strings.Contains(p.Endpoint, GCM_WEBPUSH_ENDPOINT) || strings.Contains(p.Endpoint, GCM_URL) {
		is = true
	}

	return
}

func (p PushSubscription) getEncryptionHeaderKey() string {
	if p.hasAuth() {
		return "Crypto-Key"
	}
	return "Encryption-Key"
}

func (p PushSubscription) getContentEncodingValue() string {
	if p.Version == 1 {
		return "aesgcm"
	}

	return "aesgcm128"
}
