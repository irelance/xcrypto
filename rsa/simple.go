package rsa

import (
	"github.com/irelance/xcrypto"
	"crypto"
)

func NewCipherSimple(key []byte) (c *Cipher, err error) {
	c = &Cipher{
		signType:        crypto.SHA256,
		defaultKeyIsPub: true,
	}
	c.SetEncodeType(xcrypto.ENCODE_UNSAFE_TYPE_RAW)
	c.privateKey, err = ParsePrivateKey(key)
	if nil != err {
		c.publicKey, err = ParsePublicKey(key)
		if err != nil {
			return nil, ErrKeyFormatNotSupport
		}
	} else {
		c.publicKey = &c.privateKey.PublicKey
		c.defaultKeyIsPub = false
	}
	return c, nil
}

func (c *Cipher) SetDefaultKeyIsPub(d bool) bool {
	if !d && nil == c.privateKey {
		return false
	}
	c.defaultKeyIsPub = d
	return true
}

func (c *Cipher) Encrypt(data string) ([]byte, error) {
	if c.defaultKeyIsPub {
		return c.PublicEncrypt(data)
	}
	return c.PrivateEncrypt(data)
}

func (c *Cipher) Decrypt(data string) (string, error) {
	if c.defaultKeyIsPub {
		return c.PublicDecrypt(data)
	}
	return c.PrivateDecrypt(data)
}
