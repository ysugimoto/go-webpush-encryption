package webpush

import (
	"encoding/base64"
	"strings"
)

func urlSafeBase64Encode(input []byte) string {
	encoded := base64.URLEncoding.EncodeToString(input)
	return strings.TrimRight(encoded, "=")
}

func urlSafeBase64Decode(input string) ([]byte, error) {
	input += strings.Repeat("=", 5-(len(input)%4)-1)

	return base64.URLEncoding.DecodeString(input)

}

func EurlSafeBase64Encode(input []byte) string {
	return urlSafeBase64Encode(input)
}

func EurlSafeBase64Decode(input string) ([]byte, error) {
	return urlSafeBase64Decode(input)
}
