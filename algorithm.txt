package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

type EncryptOption struct {
	PadSize int
	Pad     int
	DH      string // Diffie Hellman
	Version int
}

type DecryptOption struct {
}

var savedKeys = make(map[string]*ecdsa.PrivateKey)
var keyLabels = make(map[string][]byte)

func SaveKey(id string, key *ecdsa.PrivateKey) {
	savedKeys[id] = key
}
func SaveLabel(id string, label []byte) {
	keyLabels[id] = append(label, '\x00')
}

const (
	MODE_ENCRYPT = "encrypt"
	MODE_DECRYPT = "decrypt"

	TAG_LENGTH     = 16
	KEY_LENGTH     = 16
	NONCE_LENGTH   = 12
	SHA_256_LENGTH = 32

	PAD_SIZE = 2
)

func deriveKeyNonce(salt []byte, options EncryptOption, mode string) (*keyNonce, error) {
	if salt == nil {
		return nil, errors.New("A salt is required")
	}

	if padSize == 0 {
		padSize = PAD_SIZE
	}

	s, err := extractSecretAndContext(params, mode)
	if err != nil {
		return nil, err
	}
	prk := HKDF_extract(salt, s.secret.([]byte))

	var (
		keyInfo   []byte
		nonceInfo []byte
	)

	switch padSize {
	case 1:
		keyInfo = []byte("Content-Encoding: aesgcm128")
		nonceInfo = []byte("Content-Encoding: nonce")
	case 2:
		keyInfo = info("aesgcm", s.context)
		nonceInfo = info("nonce", s.context)
	default:
		return nil, errors.New(fmt.Sprintf("Unable to set context for padSize %d", params["padSize"]))
	}

	key := HKDF_expand(prk, keyInfo, KEY_LENGTH)
	nonce := HKDF_expand(prk, nonceInfo, NONCE_LENGTH)

	return &keyNonce{key: key, nonce: nonce}, nil
}

func extractSecretAndContext(params map[string]interface{}, mode string) (*contextSecret, error) {
	cs := NewContextSecret()
	if v, ok := params["key"]; ok {
		cs.secret = v
		if len(cs.secret.([]byte)) != KEY_LENGTH {
			return nil, errors.New(fmt.Sprintf("An explicit key must be %d bytes", KEY_LENGTH))
		}
	} else if v, ok := params["dh"]; ok {
		var err error
		cs, err = extractDH(params["keyid"].(string), v.(string), mode)
		if err != nil {
			return nil, err
		}
	} else if v, ok := params["keyid"]; ok {
		key := savedKeys[v.(string)]
		cs.secret = elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	}

	if cs.secret == nil {
		return nil, errors.New("Unable to determine key")
	}
	if v, ok := params["authSecret"]; ok {
		dec, _ := base64.StdEncoding.DecodeString(v.(string))
		cs.secret = HKDF(dec, cs.secret.([]byte), info("auth", []byte{}), SHA_256_LENGTH)
	}

	return cs, nil
}

func generateNonce(base []byte, counter int) []byte {
	nonce := base[len(base)-6:]
	buf := bytes.NewReader(nonce)
	var m int
	binary.Read(buf, binary.BigEndian, &m)
	x := ((m^counter)&0xffffff + (((m/0x1000000)^(counter/0x1000000))&0xffffff)*0x1000000)
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, x)
	return append(base[:len(base)-6], b.Bytes()...)

}

func extractDH(keyId string, dh string, mode string) (*contextSecret, error) {
	if _, ok := savedKeys[keyId]; !ok {
		return nil, errors.New(fmt.Sprintf("No known DH key for %s", keyId))
	}
	if _, ok := keyLabels[keyId]; !ok {
		return nil, errors.New(fmt.Sprintf("No known DH key label for %s", keyId))
	}

	share, err := base64.StdEncoding.DecodeString(dh)
	if err != nil {
		return nil, err
	}
	key := savedKeys[keyId]
	curve := elliptic.P256()
	var senderPubKey []byte
	var receiverPubKey []byte

	switch mode {
	case MODE_ENCRYPT:
		senderPubKey = elliptic.Marshal(curve, key.PublicKey.X, key.PublicKey.Y)
		receiverPubKey = share
	case MODE_DECRYPT:
		senderPubKey = share
		receiverPubKey = elliptic.Marshal(curve, key.PublicKey.X, key.PublicKey.Y)
	default:
		return nil, errors.New(fmt.Sprintf("Unknown mode only %s and %s supported", MODE_ENCRYPT, MODE_DECRYPT))
	}

	x, y := elliptic.Unmarshal(curve, share)

	cs := NewContextSecret()
	cs.secret, _ = curve.ScalarMult(x, y, key.D.Bytes())
	cs.context = append(cs.context, keyLabels[keyId]...)
	cs.context = append(cs.context, lengthPrefix(receiverPubKey)...)
	cs.context = append(cs.context, lengthPrefix(senderPubKey)...)

	return cs, nil
}

func lengthPrefix(buffer []byte) []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, len(buffer))
	return append(b.Bytes(), buffer...)
}

func extractSalt(salt string) ([]byte, error) {
	if salt == "" {
		return nil, errors.New("A salt is required")
	}

	dec, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, errors.New("base644 decoding failed")
	} else if len(dec) != KEY_LENGTH {
		return nil, errors.New(fmt.Sprintf("The salt parameter must be %d bytes", KEY_LENGTH))
	}

	return dec, nil
}

func info(base string, context []byte) (ret []byte) {
	ret = append(ret, []byte("Content-Encoding: "+base)...)
	ret = append(ret, '\x00')
	ret = append(ret, context...)
	return
}

func determineRecordSize(params map[string]interface{}) (int, error) {
	rs, err := strconv.Atoi(params["rs"].(string))
	if err != nil {
		return 4096, nil
	}
	padSize := PAD_SIZE
	if v, ok := params["padSize"]; ok {
		padSize = v.(int)
	}
	if rs <= padSize {
		return 0, errors.New(fmt.Sprintf("The rs parameter has to be greater than %d", padSize))
	}

	return rs, nil
}
