package webpush

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var TAIL_EQUAL = regexp.MustCompile("=+$")

func urlSafeBase64Encode(input []byte) string {
	encoded := base64.URLEncoding.EncodeToString(input)
	//return TAIL_EQUAL.ReplaceAllString(encoded, "")
	//encoded = strings.Replace(encoded, "+", "_", -1)
	//encoded = strings.Replace(encoded, "/", "-", -1)
	encoded = strings.Replace(encoded, "=", "-", -1)

	return encoded
}

func urlSafeBase64Decode(input string) ([]byte, error) {
	//input = strings.Replace(input, "_", "+", -1)
	//input = strings.Replace(input, "-", "/", -1)
	input = strings.Replace(input, "-", "=", -1)

	return base64.URLEncoding.DecodeString(input)
}
