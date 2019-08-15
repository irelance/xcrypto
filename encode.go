package xcrypto

import (
	"encoding/base64"
	"encoding/hex"
)

type EncodeType uint

const (
	ENCODE_UNSAFE_TYPE_RAW EncodeType = iota
	ENCODE_SAFE_TYPE_BASE64
	ENCODE_SAFE_TYPE_HEX
)

type Cipher struct {
	encodeType EncodeType
}

func (r *Cipher) SetEncodeType(encodeType EncodeType) *Cipher {
	r.encodeType = encodeType
	return r
}

func (c *Cipher) EncodeData(encrypt []byte) []byte {
	switch c.encodeType {
	case ENCODE_SAFE_TYPE_BASE64:
		return []byte(base64.StdEncoding.EncodeToString(encrypt))
	case ENCODE_SAFE_TYPE_HEX:
		return []byte(hex.EncodeToString(encrypt))
	}
	return encrypt
}

func (c *Cipher) DecodeData(decrypt string) ([]byte, error) {
	switch c.encodeType {
	case ENCODE_SAFE_TYPE_BASE64:
		return base64.StdEncoding.DecodeString(decrypt)
	case ENCODE_SAFE_TYPE_HEX:
		return hex.DecodeString(decrypt)
	}
	return []byte(decrypt), nil
}
