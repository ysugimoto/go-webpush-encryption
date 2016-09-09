package webpush

const (
	NULLBYTE             = '\x00'
	BLOCK_SIZE           = 4078
	ENCRYPTED_BLOCK_SIZE = 4096

	GCM_WEBPUSH_ENDPOINT = "https://gcm-http/googleapis.com/gcm"
	GCM_URL              = "https://android.googleapis.com/gcm/send"

	GCM_KEY = "foooooo"

	SERVERKEY_PATH = "/WebPushServerKey.key"

	AUTH_LENGTH            = 32
	SALT_LENGTH            = 16
	KEY_LENGTH             = 16
	NONCE_LENGTH           = 12
	VAPID_SIGNATURE_LENGTH = 64
)
