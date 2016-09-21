package webpush

import (
	wp "github.com/ysugimoto/go-webpush-encryption"
	"testing"
)

func TestURLBase64Decode(t *testing.T) {
	str := "vVVV51qQH1N2tWbZgv2MRQ"

	dec, err := wp.EurlSafeBase64Decode(str)
	if err != nil {
		t.Error(err)
	}

	enc := wp.EurlSafeBase64Encode(dec)

	if enc != str {
		t.Error(enc)
	}
}
