package rsa

import (
	"io/ioutil"
	"testing"
)

func TestSimpleNoPrivateKeyErrors(t *testing.T) {
	key, err := ioutil.ReadFile("./test/public.pkcs1.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	PubCipher, err := NewCipherSimple(key)
	if err != nil {
		t.Fatal(err.Error())
	}
	if ok := PubCipher.SetDefaultKeyIsPub(false); ok {
		t.Fatal("no private key but set default key to private key")
	}
	_, err = PubCipher.PrivateEncrypt("test")
	if err != ErrPriKeyIsNeed {
		t.Fatal("no private key but not return error")
	}
}

func TestSimple(t *testing.T) {
	data := "Hello World!"
	key, err := ioutil.ReadFile("./test/public.pkcs1.pem")
	if err != nil {
		t.Fatal(err.Error())
	}
	PubCipher, err := NewCipherSimple(key)
	if err != nil {
		t.Fatal(err.Error())
	}
	//
	key, err = ioutil.ReadFile("./test/private.pkcs8")
	if err != nil {
		t.Fatal(err.Error())
	}
	PriCipher, err := NewCipherSimple(key)
	if err != nil {
		t.Fatal(err.Error())
	}

	//
	raw, err := PubCipher.Encrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}
	res, err := PriCipher.Decrypt(string(raw))
	if err != nil {
		t.Fatal(err.Error())
	}
	if res != data {
		t.Fatal("not equal")
	}

	//
	raw, err = PriCipher.Encrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}
	res, err = PubCipher.Decrypt(string(raw))
	if err != nil {
		t.Fatal(err.Error())
	}
	if res != data {
		t.Fatal("not equal")
	}
}
