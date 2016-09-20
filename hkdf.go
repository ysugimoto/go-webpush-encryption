package webpush

import (
	"crypto/hmac"
	"crypto/sha256"
)

func HKDF(salt, ikm, info []byte, size int) []byte {
	return HKDF_expand(HKDF_extract(salt, ikm), info, size)
}

func HKDF_extract(key, input []byte) []byte {
	h := hmac.New(sha256.New, key)
	return h.Sum(input)
}

func HKDF_expand(prk, ikm []byte, size int) []byte {
	h := hmac.New(sha256.New, prk)
	ikm = append(ikm, '\x01')
	sum := h.Sum(ikm)
	if size <= 32 {
		return sum[:size]
	}
	return sum
}
