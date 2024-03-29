package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"encoding/base64"
	"encoding/json"

	"fmt"
	"io/ioutil"
	"math/big"
	"os"
)

type KeyManager struct {
	serverPrivateKey *ecdsa.PrivateKey
	serverPublicKey  ecdsa.PublicKey
	localPrivateKey  *ecdsa.PrivateKey
	localPublicKey   ecdsa.PublicKey
	userPublicKey    ecdsa.PublicKey
	sharedSecretKey  []byte
}

func (k *KeyManager) setLocalKey(key *ecdsa.PrivateKey) {
	k.localPrivateKey = key
	k.localPublicKey = key.PublicKey
}

func (k *KeyManager) setServerKey(key *ecdsa.PrivateKey) {
	k.serverPrivateKey = key
	k.serverPublicKey = key.PublicKey
}

func (k *KeyManager) setUserPublicKey(key ecdsa.PublicKey) {
	k.userPublicKey = key
}

func (k *KeyManager) setSharedKey(key []byte) {
	k.sharedSecretKey = key
}

func GetLocalKey() *ecdsa.PrivateKey {
	return keyManager.localPrivateKey
}
func GetServerKey() *ecdsa.PrivateKey {
	return keyManager.serverPrivateKey
}
func GetSharedKey() []byte {
	return keyManager.sharedSecretKey
}
func GetUserKey() ecdsa.PublicKey {
	return keyManager.userPublicKey
}

var keyManager *KeyManager
var Curve = elliptic.P256()

type serverKeyMap struct {
	X string `json:"x"`
	Y string `json:"y"`
	D string `json:"d"`
}

func init() {
	keyManager = &KeyManager{
		sharedSecretKey: []byte{},
	}
	var serverKey *ecdsa.PrivateKey

	if _, err := os.Stat(SERVERKEY_PATH); err == nil {
		serverKey = importServerKeyFromFile()
	} else {
		serverKey = generateNewServerKey()
	}

	fmt.Printf(
		"Server PublicKey: %s\n",
		urlSafeBase64Encode(elliptic.Marshal(Curve, serverKey.PublicKey.X, serverKey.PublicKey.Y)),
	)

	keyManager.setServerKey(serverKey)
}

func importServerKeyFromFile() *ecdsa.PrivateKey {
	buf, _ := ioutil.ReadFile(SERVERKEY_PATH)

	km := serverKeyMap{}
	err := json.Unmarshal(buf, &km)
	if err != nil {
		panic(err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: Curve,
			X:     toBigInt(km.X),
			Y:     toBigInt(km.Y),
		},
		D: toBigInt(km.D),
	}
}

func generateNewServerKey() *ecdsa.PrivateKey {
	serverKey, err := ecdsa.GenerateKey(Curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	km := serverKeyMap{
		X: base64.StdEncoding.EncodeToString(serverKey.PublicKey.X.Bytes()),
		Y: base64.StdEncoding.EncodeToString(serverKey.PublicKey.Y.Bytes()),
		D: base64.StdEncoding.EncodeToString(serverKey.D.Bytes()),
	}

	buf, err := json.Marshal(km)
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(SERVERKEY_PATH, buf, 0777); err != nil {
		panic(err)
	}

	return serverKey
}

func toBigInt(keyStr string) *big.Int {
	dec, _ := base64.StdEncoding.DecodeString(keyStr)
	bi := new(big.Int)
	bi.SetBytes(dec)

	return bi
}

func importUserPublicKey(pubKey string) (ecdsa.PublicKey, error) {
	dec, _ := urlSafeBase64Decode(pubKey)

	X, Y := elliptic.Unmarshal(Curve, dec)
	return ecdsa.PublicKey{
		Curve: Curve,
		X:     X,
		Y:     Y,
	}, nil
}
