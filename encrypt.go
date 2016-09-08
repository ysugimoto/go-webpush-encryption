package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

func encrypt(buffer, key salt []byte, options EncryptOption) ([]byte, error) {
	kn, err := deriveKeyNonce(salt, options, MODE_ENCRYPT)
	if err != nil {
		return nil, err
	}

	rs, err := determineRecordSize(params)
	if err != nil {
		return nil, err
	}

	start := 0
	result := []byte{}
	padSize := PAD_SIZE
	if v, ok := params["padSize"]; ok {
		padSize = v.(int)
	}
	pad := 0
	if v, ok := params["pad"]; ok {
		pad = v.(int)
	}

	for index, _ := range buffer {
		a := 1<<uint8(padSize*8) - 1
		recordPad := int(math.Min(float64(a), math.Min(float64(rs-padSize-1), float64(pad))))

		pad -= recordPad

		end := math.Min(float64(start+rs-padSize-recordPad), float64(len(buffer)))
		block, err := encryptRecord(kn, index, buffer[start:int(end)], recordPad, padSize)
		if err != nil {
			return nil, err
		}
		result = append(result, block...)
		start += rs - padSize - recordPad
	}

	if pad > 0 {
		return nil, errors.New(fmt.Sprintf("Unable to pad by requested amount, %d remaining", pad))
	}

	return result, nil
}

func encryptRecord(key *keyNonce, counter int, buffer []byte, pad, padSize int) ([]byte, error) {
	nonce := generateNonce(key.nonce, counter)
	block, err := aes.NewCipher(key.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return nil, err
	}
	if padSize == 0 {
		padSize = PAD_SIZE
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pad)
	padding := buf.Bytes()
	for len(padding) < pad+padSize {
		padding = append(padding, 0)
	}

	return gcm.Seal(nil, nonce, buffer, padding), nil

}
