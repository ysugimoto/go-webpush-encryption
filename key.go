package webpush

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

var savedKeys = make(map[string][]byte)

const (
	MODE_ENCRYPT = "encrypt"
	MODE_DECRYPT = "decrpyt"

	KEY_LENGTH     = 16
	NONCE_LENGTH   = 12
	SHA_256_LENGTH = 32
)

func encrypt(buffer []byte, params map[string]interface{}) ([]byte, error) {
	kn, err := deriveKeyAndNonce(params, MODE_ENCRYPT)
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
}

func deriveKeyAndNonce(params map[string]interface{}, mode int) (*keyNonce, error) {
	padSize := PAD_SIZE
	if v, ok := params["padSize"]; ok {
		padSize = v.(int)
	}
	salt, err := extractSalt(params["salt"])
	if err != nil {
		return nil, err
	}
	s, err := extractSecretAndContext(params, mode)
	if err != nil {
		return nil, err
	}
	prk := HKDF_extract(salt, s.secret)

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
		return nil, errors.New("Unable to set context for padSize " + params["padSize"])
	}

	return NewKeyNonce(
		HKDF_expand(prk, keyInfo, KEY_LENGTH),
		HKDF_expand(prk, nonceInfo, NONCE_LENGTH),
	), nil
}

func extractSalt(salt string) ([]byte, error) {
	if salt == nil {
		return nil, errors.New("A salt is required")
	}

	dec, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, errors.New("base644 decoding failed")
	} else if len(dec) != KEY_LENGTH {
		return nil, errors.New("The salt parameter must be " + KEY_LENGTH + " bytes")
	}

	return dec, nil
}

func extractSecretAndContext(params map[string]interface{}, mode int) (*contextSecret, error) {
	cs := NewContextSecret()
	if v, ok := params["key"]; ok {
		cs.secret, _ = base64.StdEncoding.DecodeString(v)
		if len(cs.secret) != KEY_LENGTH {
			return nil, errors.New("An explicit key must be " + KEY_LENGTH + " bytes")
		}
	} else if v, ok := params["dh"]; ok {
		cs = extractDH(params["keyid"].(string), params["dh"].([]byte), mode)
	} else if v, ok := params["keyid"]; ok {
		cs.secret = savedKeys[params["keyid"].(string)]
	}

	if cs.secret == nil {
		return nil, errors.New("Unable to determine key")
	}
	if v, ok := params["authSecret"]; ok {
		cs.secret = HKDF(
			base64.StdEncoding.DecodeString(v.(string)),
			cs.secret,
			info("auth", []byte{}),
			SHA_256_LENGTH,
		)
	}

	return cs, nil
}

func info(base string, context []byte) (ret []byte) {
	ret = append(ret, []byte("Content-Encoding: "+base)...)
	ret = append(ret, byte("\x00"))
	ret = append(ret, context...)
	return
}

func determineRecordSize(params map[string]interface{}) (int, err) {
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

	return rs
}
