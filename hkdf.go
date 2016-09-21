package webpush

// HMAC-based Extract-and-Expand Key Derivation Function (HKDF) Implements
// @see https://tools.ietf.org/html/rfc5869
//
// This functions supports HMAC-SHA-256 algorithm only.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Extract and Expand
func HKDF(salt, ikm, info []byte, size int) []byte {
	return HKDF_expand(HKDF_extract(salt, ikm), info, size)
}

// Extract function
func HKDF_extract(key, input []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(input)
	return h.Sum(nil)
}

// Expand function
func HKDF_expand(prk, ikm []byte, size int) (OKM []byte) {
	T := []byte{}
	C := 0

	for len(OKM) < size {
		C++
		b := new(bytes.Buffer)
		if err := binary.Write(b, binary.BigEndian, uint8(C)); err != nil {
			panic(err)
		}
		T = HKDF_extract(prk, append(T, append(ikm, b.Bytes()...)...))
		OKM = append(OKM, T...)
	}

	return OKM[:size]
}
