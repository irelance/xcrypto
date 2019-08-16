package rsa

import (
	"github.com/irelance/xcrypto"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
)

const (
	CHAR_SET = "UTF-8"
)

type PaddingType uint

const (
	PADDING_PKCS1 PaddingType = 1 + iota
	//todo
	//PADDING_OAEP
	//PADDING_SSLV23
	//PADDING_NO
)

type BlockCryptoMode uint

const (
	BLOCK_CRYPTO_MODE_ECB PaddingType = 1 + iota
	//todo
	//BLOCK_CRYPTO_MODE_CBC
	//BLOCK_CRYPTO_MODE_OFB
	//BLOCK_CRYPTO_MODE_CFB
)

const (
	PUB_KEY_TYPE_PKCS1 = "RSA PUBLIC KEY"
	PUB_KEY_TYPE_PKCS8 = "PUBLIC KEY"
	//todo
	//PUB_KEY_TYPE_SSH2  = "SSH2 PUBLIC KEY"
)

const (
	PRI_KEY_TYPE_PKCS1 = "RSA PRIVATE KEY"
	PRI_KEY_TYPE_PKCS8 = "PRIVATE KEY"
	//todo
	//PRI_KEY_TYPE_OPENSSH = "OPENSSH PRIVATE KEY"
)

type Cipher struct {
	xcrypto.Cipher
	publicKey       *rsa.PublicKey
	privateKey      *rsa.PrivateKey
	signType        crypto.Hash
	defaultKeyIsPub bool
}

func CreateKeys(publicKeyWriter, privateKeyWriter io.Writer, keyLength int) error {
	// gen private key
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}
	derStream, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  PRI_KEY_TYPE_PKCS8,
		Bytes: derStream,
	}
	err = pem.Encode(privateKeyWriter, block)
	if err != nil {
		return err
	}

	// gen public key
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  PUB_KEY_TYPE_PKCS8,
		Bytes: derPkix,
	}
	err = pem.Encode(publicKeyWriter, block)
	if err != nil {
		return err
	}

	return nil
}

//todo support passphrase

func ParsePublicKey(publicKey []byte) (key *rsa.PublicKey, err error) {
	var ok bool
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, ErrOnKeyPemDecode
	}
	switch block.Type {
	case PUB_KEY_TYPE_PKCS8:
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok = pubInterface.(*rsa.PublicKey)
		if !ok {
			return nil, ErrPubKeyFormatNotSupport
		}
	case PUB_KEY_TYPE_PKCS1:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	default:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, ErrPubKeyFormatNotSupport
		}
	}
	return key, nil
}

func ParsePrivateKey(privateKey []byte) (key *rsa.PrivateKey, err error) {
	var ok bool
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, ErrOnKeyPemDecode
	}
	switch block.Type {
	case PRI_KEY_TYPE_PKCS8:
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		key, ok = priv.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrPriKeyFormatNotSupport
		}
	case PRI_KEY_TYPE_PKCS1:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	default:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrPriKeyFormatNotSupport
		}
	}
	return key, nil
}

func NewCipher(publicKey []byte, privateKey []byte) (c *Cipher, err error) {
	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pri, err := ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	c = &Cipher{
		publicKey:       pub,
		privateKey:      pri,
		signType:        crypto.SHA256,
		defaultKeyIsPub: true,
	}
	c.SetEncodeType(xcrypto.ENCODE_UNSAFE_TYPE_RAW)
	return c, nil
}

func (r *Cipher) SetVSignType(signType crypto.Hash) *Cipher {
	r.signType = signType
	return r
}

func (c *Cipher) PublicEncrypt(data string) ([]byte, error) {
	partLen := c.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, c.publicKey, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(bts)
	}

	return c.EncodeData(buffer.Bytes()), nil
}

func (c *Cipher) PrivateDecrypt(encrypted string) (string, error) {
	if nil == c.privateKey {
		return "", ErrPriKeyIsNeed
	}
	partLen := c.publicKey.N.BitLen() / 8
	raw, err := c.DecodeData(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, c.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

func (c *Cipher) PrivateEncrypt(data string) ([]byte, error) {
	if nil == c.privateKey {
		return nil, ErrPriKeyIsNeed
	}
	partLen := c.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := PrivateEncrypt(c.privateKey, chunk)
		if err != nil {
			return nil, err
		}

		buffer.Write(bts)
	}

	return c.EncodeData(buffer.Bytes()), nil
}

func (c *Cipher) PublicDecrypt(encrypted string) (string, error) {
	partLen := c.publicKey.N.BitLen() / 8
	raw, err := c.DecodeData(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := PublicDecrypt(c.publicKey, chunk)

		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

func (c *Cipher) Sign(data string) ([]byte, error) {
	if nil == c.privateKey {
		return nil, ErrPriKeyIsNeed
	}
	h := c.signType.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, c.signType, hashed)
	if err != nil {
		return nil, err
	}
	return c.EncodeData([]byte(sign)), err
}

func (c *Cipher) Verify(data string, sign string) error {
	h := c.signType.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := c.DecodeData(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(c.publicKey, c.signType, hashed, decodedSign)
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
