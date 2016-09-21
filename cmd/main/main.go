package main

import (
	"fmt"
	wp "github.com/ysugimoto/go-webpush-encryption"
	"net/url"
)

const AUTH = "auth-secret"
const KEY = "browser public key"
const ENDPOINT = "endpoint"
const SUBJECT = "your site URL"

func main() {
	u, _ := url.Parse(ENDPOINT)
	ss := wp.PushSubscription{
		Keys: wp.PushSubscriptionKey{
			P256DH: KEY,
			Auth:   AUTH,
		},
		Payload:  "SampleSample",
		Version:  1,
		Endpoint: ENDPOINT,
		JWT:      wp.NewJWTClaim(fmt.Sprintf("%s://%s", u.Scheme, u.Host), SUBJECT, 0),
	}

	wp.SendWebPush(ss)
}
