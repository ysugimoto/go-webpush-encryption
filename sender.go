package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

type PushSubscription struct {
	PublicKey string   `json:"key"`
	Auth      string   `json:"auth"`
	Payload   string   `json:"payload"`
	Version   int      `json:"int"`
	Endpoint  string   `json:"endpoint"`
	JWT       JWTClaim `json:"jwt"`
}

func sendWebPush(ss PushSubscription) {
	version := 0

	info := NewJWTClaim("audience", "subject", 0)

	var sharedSecretKey []byte
	var encryptedData []byte

	salt := make([]byte, SALT_LENGTH)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}

	if ss.PublicKey != "" && ss.Payload != "" {
		localKey, err := ecdsa.GenerateKey(Curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		keyManager.setLocalKey(localKey)
		userPublicKey, err := importUserPublicKey(ss.PublicKey)
		if err != nil {
			panic(err)
		}
		keyManager.setUserPublicKey(userPublicKey)

		x, _ := Curve.ScalarMult(userPublicKey.X, userPublicKey.Y, localKey.D.Bytes())
		if err != nil {
			panic(err)
		}
		keyManager.setSharedKey(x.Bytes())

		if len(sharedSecretKey) > 0 {
			var prk, ikm []byte
			context := []byte{}

			if ss.Auth != "" {
				decAuth, err := urlSafeBase64Decode(ss.Auth)
				if err != nil {
					panic(err)
				}
				tmpPrk := HKDF_extract(decAuth, sharedSecretKey)
				bufferAuth := []byte("Content-Encoding: auth")
				ikm = HKDF_expand(tmpPrk, append(bufferAuth, NULLBYTE), AUTH_LENGTH)

				receiverKey := elliptic.Marshal(Curve, keyManager.userPublicKey.X, keyManager.userPublicKey.Y)
				senderKey := elliptic.Marshal(Curve, keyManager.localPublicKey.X, keyManager.localPublicKey.Y)
				context = append(context, append([]byte("P-256"), NULLBYTE)...)

				b := new(bytes.Buffer)
				binary.Write(b, binary.BigEndian, len(receiverKey))
				context = append(context, append(b.Bytes(), receiverKey...)...)

				b = new(bytes.Buffer)
				binary.Write(b, binary.BigEndian, len(senderKey))
				context = append(context, append(b.Bytes(), senderKey...)...)
			} else {
				ikm = sharedSecretKey
			}
			prk = HKDF_extract(salt, ikm)

			if len(prk) > 0 {
				contextSize := len(context)
				var bufferCEK []byte
				if version == 1 {
					bufferCEK = []byte("Content-Encoding: aesgcm")
				} else {
					bufferCEK = []byte("Content-Encoding: aesgcm128")
				}
				bufferNonce := []byte("Content-Encoding: nonce")

				if contextSize > 0 {
					bufferCEK = append(bufferCEK, NULLBYTE)
					bufferCEK = append(bufferCEK, context...)
					bufferNonce = append(bufferNonce, NULLBYTE)
					bufferNonce = append(bufferNonce, context...)
				}

				hashInfoKey := HKDF_expand(prk, bufferCEK, KEY_LENGTH)
				hashInfoNonce := HKDF_expand(prk, bufferNonce, NONCE_LENGTH)

				e := NewEncrypter(hashInfoKey)
				encryptedData = e.encrypt([]byte(ss.Payload), hashInfoNonce)
			}
		}
	}

	request := NewPushRequest(ss.Endpoint, encryptedData)
	if len(encryptedData) > 0 {
		request.setHeader("Content-Type", "application/octet-stream")
		request.setHeader("Content-Length", fmt.Sprint(len(encryptedData)))

		eck := urlSafeBase64Encode(
			elliptic.Marshal(Curve, keyManager.localPublicKey.X, keyManager.localPublicKey.Y),
		)
		if ss.Auth != "" {
			request.setHeader("Crypto-Key", fmt.Sprintf("keyid=p256dh;dh=%s", eck))
		} else {
			request.setHeader("Encryption-Key", fmt.Sprintf("keyid=p256dh;dh=%s", eck))
		}

		request.setHeader("Encryption", fmt.Sprintf("keyid=p256dh;salt=%s", urlSafeBase64Encode(salt)))

		if version == 1 {
			request.setHeader("Content-Encoding", "aesgcm")
		} else {
			request.setHeader("Content-Encoding", "aesgcm128")
		}
	}

	request.setHeader("TTL", fmt.Sprint(2*24*60*60))

	if strings.Contains(ss.Endpoint, GCM_WEBPUSH_ENDPOINT) || strings.Contains(ss.Endpoint, GCM_URL) {
		request.setHeader("Authorization", fmt.Sprintf("key=%s", GCM_KEY))
	}

	if info != nil {
		jwtHeader := NewJWTHeader()
		now := time.Now().UnixNano() / int64(time.Millisecond)
		jwtClaim := NewJWTClaim(info.Audience, info.Subject, now+12*60*60)
		claim := generateJWTClaimString(jwtHeader, jwtClaim)

		// VAPID
		x, y, err := ecdsa.Sign(rand.Reader, keyManager.serverPrivateKey, []byte(claim))
		if err != nil {
			panic(err)
		}
		asn1 := elliptic.Marshal(Curve, x, y)
		signature := make([]byte, VAPID_SIGNATURE_LENGTH)

		l1 := int(asn1[3])
		pos := 4 + l1 - 32
		signature = append(signature, asn1[pos:(pos+32)]...)
		pos += 33

		l2 := int(asn1[pos])
		pos += 1 + l2 - 32
		signature = append(signature, asn1[pos:(pos+32)]...)

		p256ecdsa := urlSafeBase64Encode(
			elliptic.Marshal(Curve, keyManager.serverPublicKey.X, keyManager.serverPublicKey.Y),
		)
		request.appendHeader("Crypto-Key", ";p256ecdsa="+p256ecdsa)
		request.setHeader("Authorization", fmt.Sprintf("WebPush %s.%s", claim, urlSafeBase64Encode(signature)))
	}

	response, err := request.send()
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

}
