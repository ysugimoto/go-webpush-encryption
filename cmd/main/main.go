package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

func main() {
	p256 := elliptic.P256()
	key, err := ecdsa.GenerateKey(p256, rand.Reader)

	if err != nil {
		fmt.Println(err)
		return
	}

	x, _ := p256.ScalarMult(key.PublicKey.X, key.PublicKey.Y, key.D.Bytes())
	fmt.Printf("%x", x.Bytes())
}
