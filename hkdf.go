package webpush

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func HKDF(salt, ikm, info []byte, size int) []byte {
	return HKDF_expand(HKDF_extract(salt, ikm), info, size)
}

func HKDF_extract(key, input []byte) []byte {
	h := hmac.New(sha256.New, key)
	return h.Sum(input)
}

func HKDF_expand(prk, ikm []byte, size int) []byte {
	out := []byte{}
	T := []byte{}
	counter := 0
	for len(out) < size {
		cBuf := new(bytes.Buffer)
		counter++
		binary.Write(cBuf, binary.BigEndian, counter)
		I := []byte{}
		I = append(I, ikm...)
		I = append(I, cBuf.Bytes()...)
		T = append(T, I...)
		T = HKDF_extract(prk, T)
		out = append(out, T...)
	}

	return out[:size]
}
