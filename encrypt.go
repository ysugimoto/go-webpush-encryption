package webpush

import (
	"crypto/aes"
	"crypto/cipher"
)

type Encrypter struct {
	c       cipher.AEAD
	padding []byte
}

func NewEncrypter(key []byte) *Encrypter {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	return &Encrypter{
		c:       gcm,
		padding: []byte{NULLBYTE, NULLBYTE},
	}
}

func (e *Encrypter) encrypt(payload, nonce []byte) (encrypted []byte) {
	start := 0
	size := len(payload)

	for i := 0; start < size; i++ {
		if start+BLOCK_SIZE > size {
			d := e.encryptRecord(payload[start:], nonce, i)
			encrypted = append(encrypted, d...)
			break
		} else {
			d := e.encryptRecord(payload[start:(start+BLOCK_SIZE)], nonce, i)
			encrypted = append(encrypted, d...)
		}
		start += BLOCK_SIZE
	}

	return encrypted
}

func (e *Encrypter) encryptRecord(chunk, nonce []byte, counter int) []byte {
	c := append(e.padding, chunk...)
	n := e.generateNonce(nonce, uint(counter))

	return e.c.Seal(nil, n, c, nil)
}

func (e *Encrypter) generateNonce(n []byte, c uint) []byte {
	nonce := make([]byte, 6)
	pos := len(n) - 6

	for i := pos; i < len(n); i++ {
		b := uint(n[i]) ^ c
		nonce = append(nonce, byte(b))
	}

	return append(n[:pos], nonce...)
}
