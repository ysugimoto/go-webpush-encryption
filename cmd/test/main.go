package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"fmt"
	"io"
)

var key = make([]byte, 16)
var nonce = make([]byte, 12)
var text = []byte("Foobarbazz")
var message = []byte{}

func init() {
	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, nonce)
	for i := 0; i < 1000; i++ {
		message = append(message, text...)
	}
}

const BLOCK_SIZE = 4078
const ENCRYPTED_BLOCK_SIZE = 4096

func main() {

	// encrypt
	start := 0
	size := len(message)
	fmt.Println(size)
	encrypted := []byte{}
	for i := 0; start < size; i++ {
		var e []byte
		if start+BLOCK_SIZE > size {
			e = enc(message[start:], key, nonce, i)
			fmt.Println(len(e))
			encrypted = append(encrypted, e...)
			break
		} else {
			e = enc(message[start:(start+BLOCK_SIZE)], key, nonce, i)
			fmt.Println(len(e))
			encrypted = append(encrypted, e...)
		}
		start += BLOCK_SIZE
	}

	fmt.Println(len(encrypted))

	// decrypt
	start = 0
	size = len(encrypted)
	decrypted := []byte{}
	for i := 0; start < size; i++ {
		var e []byte
		if start+ENCRYPTED_BLOCK_SIZE > size {
			e = dec(encrypted[start:], key, nonce, i)
			fmt.Println(len(e))
			decrypted = append(decrypted, e...)
		} else {
			e = dec(encrypted[start:(start+ENCRYPTED_BLOCK_SIZE)], key, nonce, i)
			fmt.Println(len(e))
			decrypted = append(decrypted, e...)
		}
		start += ENCRYPTED_BLOCK_SIZE
	}

	fmt.Println(len(decrypted))

	if string(message) == string(decrypted) {
		fmt.Println("Enc/Dec success!!")
	}

}

func enc(message, key, nonce []byte, counter int) []byte {
	m := []byte{'\x00', '\x00'}
	m = append(m, message...)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	cipherText := gcm.Seal(nil, nonce, m, nil)
	return cipherText
}

func dec(message, key, nonce []byte, counter int) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	text, err := gcm.Open(nil, nonce, message, nil)
	if err != nil {
		panic(err)
	}
	return text[2:]
}
