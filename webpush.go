package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	NULLBYTE             = '\x00'
	BLOCK_SIZE           = 4078
	ENCRYPTED_BLOCK_SIZE = 4096

	GCM_WEBPUSH_ENDPOINT = "https://gcm-http/googleapis.com/gcm"
	GCM_URL              = "https://android.googleapis.com/gcm/send"

	GCM_KEY = "GCM Server Key Here"

	SERVERKEY_PATH = "/WebPushServerKey.key"

	AUTH_LENGTH            = 32
	SALT_LENGTH            = 16
	KEY_LENGTH             = 16
	NONCE_LENGTH           = 12
	VAPID_SIGNATURE_LENGTH = 64
)

func sendWebPush(ss PushSubscription) {
	var encryptedData []byte

	salt := make([]byte, SALT_LENGTH)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}

	if ss.hasPayload() {
		encryptedData = encrypt(ss, salt)
	}

	request := NewPushRequest(ss.Endpoint, encryptedData)
	if len(encryptedData) > 0 {
		request.setHeader("Content-Type", "application/octet-stream")
		request.setHeader("Content-Length", fmt.Sprint(len(encryptedData)))

		eck := urlSafeBase64Encode(
			elliptic.Marshal(Curve, keyManager.localPublicKey.X, keyManager.localPublicKey.Y),
		)
		request.setHeader(ss.getEncryptionHeaderKey(), fmt.Sprintf("keyid=p256dh;dh=%s", eck))
		request.setHeader("Encryption", fmt.Sprintf("keyid=p256dh;salt=%s", urlSafeBase64Encode(salt)))
		request.setHeader("Content-Encoding", ss.getContentEncodingValue())
	}

	request.setHeader("TTL", fmt.Sprint(2*24*60*60))

	if ss.isGCM() {
		request.setHeader("Authorization", fmt.Sprintf("key=%s", GCM_KEY))
	}

	if ss.JWT != nil {
		jwtHeader := NewJWTHeader()
		now := time.Now().UnixNano() / int64(time.Millisecond)
		jwtClaim := NewJWTClaim(ss.JWT.Audience, ss.JWT.Subject, now+12*60*60)
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

func generateKeyContext(auth string) (ikm, context []byte) {
	decAuth, err := urlSafeBase64Decode(auth)
	if err != nil {
		panic(err)
	}
	tmpPrk := HKDF_extract(decAuth, keyManager.sharedSecretKey)
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

	return
}

func encrypt(ss PushSubscription, salt []byte) (encrypted []byte) {
	localKey, err := ecdsa.GenerateKey(Curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	keyManager.setLocalKey(localKey)
	userPublicKey, err := importUserPublicKey(ss.Keys.P256DH)
	if err != nil {
		panic(err)
	}
	keyManager.setUserPublicKey(userPublicKey)

	x, _ := Curve.ScalarMult(userPublicKey.X, userPublicKey.Y, localKey.D.Bytes())
	if err != nil {
		panic(err)
	}
	keyManager.setSharedKey(x.Bytes())

	if len(keyManager.sharedSecretKey) == 0 {
		return encrypted
	}
	var prk, ikm, context []byte

	if ss.hasAuth() {
		ikm, context = generateKeyContext(ss.Keys.Auth)
	} else {
		ikm = keyManager.sharedSecretKey
	}
	prk = HKDF_extract(salt, ikm)

	if len(prk) == 0 {
		return encrypted
	}
	return encryptPayload(prk, context, ss.Payload, ss.getContentEncodingValue())
}

func encryptPayload(prk, context []byte, payload, ce string) []byte {
	bufferCEK := []byte(fmt.Sprintf("Content-Encoding: %s", ce))
	bufferNonce := []byte("Content-Encoding: nonce")

	if len(context) > 0 {
		bufferCEK = append(bufferCEK, NULLBYTE)
		bufferCEK = append(bufferCEK, context...)
		bufferNonce = append(bufferNonce, NULLBYTE)
		bufferNonce = append(bufferNonce, context...)
	}

	key := HKDF_expand(prk, bufferCEK, KEY_LENGTH)
	nonce := HKDF_expand(prk, bufferNonce, NONCE_LENGTH)

	e := NewEncrypter(key)
	return e.encrypt([]byte(payload), nonce)
}
