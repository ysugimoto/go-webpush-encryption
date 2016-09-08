package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const NULLBYTE = '\x00'
const BLOCK_SIZE = 4078
const ENCRYPTED_BLOCK_SIZE = 4096

const GCM_WEBPUSH_ENDPOINT = "https://gcm-http/googleapis.com/gcm"
const GCM_URL = "https://android.googleapis.com/gcm/send"

const GCM_KEY = "foooooo"

type JWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type JWTClaim struct {
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	Exp string `json:"exp"`
}

func main() {
	// expected parameters
	pubKeyString := "base64-string"
	auth := "base64-string"
	endpoint := "string"
	payload := "Message body"
	version := 0

	info := JWTClaim{}

	var sharedSecretKey []byte
	var encryptedData []byte

	salt := make([]byte, 16)
	if err := io.ReadFull(rand, salt); err != nil {
		panic(err)
	}

	if pubKeyString != "" && payload != "" {
		curve := elliptic.P256()
		localPrivateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		localPublicKey := localPrivateKey.Public()
		userPublicKey, err := importUserPublicKey(curve, pubKeyString)
		if err != nil {
			panic(err)
		}

		s, err := curve.ScalarMult(userPublicKey.X, userPublicKey.Y, localPrivateKey.D.Bytes())
		if err != nil {
			panic(err)
		}
		sharedSecretKey = s

		if len(sharedSecretKey) > 0 {
			var prk, ikm []byte
			context := []byte{}

			if auth != "" {
				decAuth, err := urlSafeBase64Decode(auth)
				if err != nil {
					panic(err)
				}
				tmpPrk := HKDF_extract(decAuth, sharedSecretKey)
				bufferAuth := []byte("Content-Encoding: auth")
				ikm = HKDF_expand(tmpPrk, append(bufferAuth, NULLBYTE), 32) // @TODO: const

				receiverKey := elliptic.Marshal(curve, userPublicKey.X, userPublicKey.Y)
				senderKey := elliptic.Marshal(curve, localPublicKey.X, localPublicKey.Y)
				context = append(context, []byte("P-256")...)
				context = append(context, NULLBYTE)

				b := new(bytes.Buffer)
				binary.Write(b, binary.BigEndian, len(receiverKey))
				context = append(context, b.Bytes()...)
				context = append(context, receiverKey...)

				b = new(bytes.Buffer)
				binary.Write(b, binary.BigEndian, len(senderKey))
				context = append(context, b.Bytes()...)
				context = append(context, senderKey...)
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
					bifferCEK = []byte("Content-Encoding: aesgcm128")
				}
				bufferNonce := []byte("Content-Encoding: nonce")

				if contextSize > 0 {
					bufferCEK = append(bufferCEK, NULLBYTE)
					bufferCEK = append(bufferCEK, context...)
					bufferNonce = append(bufferNonce, NULLBYTE)
					bufferNonce = append(bufferNonce, context...)
				}

				hashInfoKey := HKDF_expand(prk, bufferCEK, 16)     // @TODO: const
				hashInfoNonce := HKDF_expand(prk, bufferNonce, 12) // @TODO: const

				start := 0
				message := []byte(payload)
				size := len(message)
				for i := 0; start < size; i++ {
					if start+BLOCK_SIZE > size {
						e := encrypt(message[start:], hashInfoKey, hashInfoNonce, i)
						encryptedData = append(encryptedData, e...)
						break
					} else {
						e := encrypt(message[start:(start+BLOCK_SIZE)], hashInfoKey, hashInfoNonce, i)
						encryptedData = append(encryptedData, e...)
					}
					start += BLOCK_SIZE
				}
			}
		}
	}

	// TODO: HTTP send
	var request *http.Request
	if len(encryptedData) == 0 {
		request := http.NewRequest("POST", endpoint, nil)
	} else {
		request := http.NewRequest("POST", endpoint, bytes.NewReader(encryptedData))
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Content-Length", len(encryptedData))
		ek := base64.StdEncoding.EncodeToString(
			elliptic.Marshal(curve, localPublicKey.X, localPublicKey.Y),
		)
		ek = strings.Replace(ek, "=", "", -1)
		ek = strings.Replace(ek, "+", "", -1)
		ek = strings.Replace(ek, "$", "", -1)
		if auth != "" {
			request.Header.Set("Crypto-Key", fmt.Sprintf("keyid=p256dh;dh=%s", ek))
		} else {
			request.Header.Set("Encryption-Key", fmt.Sprintf("keyid=p256dh;dh=%s", ek))
		}
		s := base64.StdEncoding.EncodeToString(salt)
		s = strings.Replace(s, "=", "", -1)
		s = strings.Replace(s, "+", "", -1)
		s = strings.Replace(s, "$", "", -1)
		request.Header.Set("Encryption", fmt.Sprintf("keyid=p256dh;salt=%s", s))
		if version == 1 {
			request.Header.Set("Content-Encoding", "aesgcm")
		} else {
			request.Header.Set("Content-Encoding", "aesgcm128")
		}
	}
	request.Header.Set("TTL", fmt.Sprint(2*24*60*60))

	if strings.Contains(endpoint, GCM_WEBPUSH_ENDPOINT) || strings.Contains(endpoint, GCM_URL) {
		request.Header.Set("Authorization", fmt.Sprintf("key=%s", GCM_KEY))
	}

	if info != nil {
		jwtHeader := &JWTHeader{
			Type:      "JWT",
			Algorithm: "ES256",
		}
		jwtClaim := &JWTClaim{
			Aud: info.Aud,
			Sub: info.Sub,
		}
		cur := time.Now().UnixNano() / int64(time.Millisecond)
		jwtClaim.Exp = cur + 12*60*60
		jh, _ := json.Marshal(jwtHeader)
		jh = strings.Replace(jh, "=", "", -1)
		jh = strings.Replace(jh, "+", "", -1)
		jh = strings.Replace(jh, "$", "", -1)
		jc, _ := json.Marshal(jwtClaim)
		jc = strings.Replace(jc, "=", "", -1)
		jc = strings.Replace(jc, "+", "", -1)
		jc = strings.Replace(jc, "$", "", -1)
		claim := fmt.Sprintf("%s.%s", jh, jc)

		// VAPID
		x, y, err := ecdsa.Sign(rand.Reader, localPrivateKey, []byte(claim))
		if err != nil {
			panic(err)
		}
		asn1 := elliptic.Marshal(curve, x, y)
		signature := make([]byte, 64)

		l1 := int(asn1[3])
		pos := 4 + l1 - 32
		signature = append(signature, asn1[pos:(pos+32)]...)
		pos += 33

		l2 = int(asn1[pos])
		post += 1 + l2 - 32
		signature = append(signature, asn1[pos:(post+32)]...)

		p256ecdsa := base64.StdEncoding.EncodeToString(localPrivateKey.D.Bytes())
		p256ecdsa = strings.Replace(p256ecdsa, "=", "", -1)
		p256ecdsa = strings.Replace(p256ecdsa, "+", "", -1)
		p256ecdsa = strings.Replace(p256ecdsa, "$", "", -1)
		request.Header.Set(
			"Crypto-Key",
			fmt.Sprintf("%s;p256ecdsa=%s", request.Header.Get("Crypto-Key"), p256ecdsa),
		)
		sig := base64.StdEncoding.EncodeToString(signature)
		sig = strings.Replace(sig, "=", "", -1)
		sig = strings.Replace(sig, "+", "", -1)
		sig = strings.Replace(sig, "$", "", -1)
		request.Header.Set(
			"Authorization",
			fmt.Sprintf("WebPush %s.%s", claim, sig),
		)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}
