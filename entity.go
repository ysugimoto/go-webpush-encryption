package webpush

type keyNonce struct {
	key   []byte
	nonce []byte
}

func NewKeyNonce(key, nonce []byte) *keyNonce {
	return &keyNonce{
		key:   key,
		nonce: nonce,
	}
}

type contextSecret struct {
	secret  []byte
	context []byte
}

func NewContextSecret() *contextSecret {
	return &NewContextSecret{
		secret:  nil,
		context: []byte{},
	}
}
