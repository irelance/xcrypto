package rsa

import "errors"

var (
	ErrOnKeyPemDecode         = errors.New("key pem decode error")
	ErrPriKeyFormatNotSupport = errors.New("private key format not support")
	ErrPubKeyFormatNotSupport = errors.New("public key format not support")
	ErrKeyFormatNotSupport    = errors.New("key format not support")
	ErrPriKeyIsNeed           = errors.New("private key is need")
)
