package webpush

import (
	"encoding/base64"
	"strings"
)

func urlSafeBase64Decode(input string) ([]byte, error) {
	input = strings.Replace(input, "_", "+", -1)
	input = strings.Replace(input, "-", "/", -1)
	input = strings.Replace(input, ".", "=", -1)

	return base64.StdEncoding.DecodeString(input)
}

func urlSafeBase64Encode(input []byte) string {
	encoded := base64.StdEncoding.EncodeToString(input)
	encoded = strings.Replace(encoded, "+", "_", -1)
	encoded = strings.Replace(encoded, "/", "-", -1)
	encoded = strings.Replace(encoded, "=", ".", -1)

	return encoded
}
