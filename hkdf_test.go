package webpush

import (
	"encoding/base64"
	wp "github.com/ysugimoto/go-webpush-encryption"
	"testing"
)

var KEY = []byte("123456789")
var SALT = []byte("987654321")
var IKM = []byte("Content-Encoding: aesgcm")

func TestHKDFExtract(t *testing.T) {
	ret := wp.HKDF_extract(SALT, KEY)
	enc := base64.StdEncoding.EncodeToString(ret)
	if enc != "MSJYRocROsZtPC88NRjHie71NqKYEh4NvIL8j+diHnM=" {
		t.Error(enc)
	}
}

func TestHKDFExpand32bit(t *testing.T) {
	prk := wp.HKDF_extract(SALT, KEY)
	ret := wp.HKDF_expand(prk, IKM, 32)
	enc := base64.StdEncoding.EncodeToString(ret)
	if enc != "mdaLA07Nh9c1RGMItgAWHX9rxK+f+6LmbyAxQIOcX+s=" {
		t.Error(enc)
	}
}

func TestHKDFExpand16bit(t *testing.T) {
	prk := wp.HKDF_extract(SALT, KEY)
	ret := wp.HKDF_expand(prk, IKM, 16)
	enc := base64.StdEncoding.EncodeToString(ret)
	if enc != "mdaLA07Nh9c1RGMItgAWHQ==" {
		t.Error(enc)
	}
}
