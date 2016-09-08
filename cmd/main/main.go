package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/k0kubun/pp"
)

func main() {
	p256 := elliptic.P256()
	key, err := ecdsa.GenerateKey(p256, rand.Reader)

	if err != nil {
		fmt.Println(err)
		return
	}

	pp.Print(key)
	x, _ := p256.ScalarMult(key.PublicKey.X, key.PublicKey.Y, key.D.Bytes())

	fmt.Printf("%x\n", x.Bytes())

	k := elliptic.Marshal(p256, key.PublicKey.X, key.PublicKey.Y)
	fmt.Printf("%s : %d\n", string(k), len(k))
}
