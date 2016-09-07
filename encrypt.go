package webpush

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

var savedKeys = make(map[string]*ecdsa.PrivateKey)
var keyLabels = make(map[string][]byte)

func SaveKey(id string, key *ecdsa.PrivateKey) {
	savedKeys[id] = key
}
func SaveKeyWithLabel(id string, key *ecdsa.PrivateKey, label []byte) {
	savedKeys[id] = key
	keyLabels[id] = append(label, '\x00')
}

const (
	MODE_ENCRYPT = "encrypt"
	MODE_DECRYPT = "decrpyt"

	KEY_LENGTH     = 16
	NONCE_LENGTH   = 12
	SHA_256_LENGTH = 32

	PAD_SIZE = 2
)

func encrypt(buffer []byte, params map[string]interface{}) ([]byte, error) {
	//kn, err := deriveKeyAndNonce(params, MODE_ENCRYPT)
	//if err != nil {
	//	return nil, err
	//}

	//rs, err := determineRecordSize(params)
	//if err != nil {
	//	return nil, err
	//}

	//start := 0
	//result := []byte{}
	//padSize := PAD_SIZE
	//if v, ok := params["padSize"]; ok {
	//	padSize = v.(int)
	//}

	// TODO
	return []byte{}, nil
}

func extractDH(keyId string, dh string, mode string) (*contextSecret, error) {
	if _, ok := savedKeys[keyId]; !ok {
		return nil, errors.New(fmt.Sprintf("No known DH key for %s", keyId))
	}
	if _, ok := keyLabels[keyId]; !ok {
		return nil, errors.New(fmt.Sprintf("No known DH key label for %s", keyId))
	}

	//share, err := base64.StdEncoding.DecodeString(dh)
	//if err != nil {
	//	return nil, err
	//}
	//key := savedKeys[keyId]
	//var senderPubKey []byte
	//var receiverPubKey []byte

	//switch mode {
	//case MODE_ENCRYPT:
	//	senderPubKey = key.PublicKey
	//	receiverPubKey = share
	//case MODE_DECRYPT:
	//	receiverPubKey = key
	//	senderPubKey = share
	//default:
	//	return nil, errors.New(fmt.Sprintf("Unknown mode only %s and %s supported", MODE_ENCRYPT, MODE_DECRYPT))
	//}

	cs := NewContextSecret()
	return cs, nil
	// TODO
	//return {
	//  secret: key.computeSecret(share),
	//  context: Buffer.concat([
	//    keyLabels[keyid],
	//    lengthPrefix(receiverPubKey),
	//    lengthPrefix(senderPubKey)
	//  ])
	//};
}

func deriveKeyAndNonce(params map[string]interface{}, mode string) (*keyNonce, error) {
	padSize := PAD_SIZE
	if v, ok := params["padSize"]; ok {
		padSize = v.(int)
	}
	salt, err := extractSalt(params["salt"].(string))
	if err != nil {
		return nil, err
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

	return NewKeyNonce(
		HKDF_expand(prk, keyInfo, KEY_LENGTH),
		HKDF_expand(prk, nonceInfo, NONCE_LENGTH),
	), nil
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
		cs.secret = savedKeys[v.(string)]
	}

	if cs.secret == nil {
		return nil, errors.New("Unable to determine key")
	}
	if v, ok := params["authSecret"]; ok {
		dec, _ := base64.StdEncoding.DecodeString(v.(string))
		cs.secret = HKDF(
			dec,
			cs.secret.([]byte),
			info("auth", []byte{}),
			SHA_256_LENGTH,
		)
	}

	return cs, nil
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
