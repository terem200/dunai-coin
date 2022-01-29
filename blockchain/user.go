package blockchain

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "github.com/mattn/go-sqlite3"
)

const (
	KEY_SIZE = 512 // TODO increase
)

type User struct {
	PrivateKey *rsa.PrivateKey
}

func NewUser() *User {
	return &User{
		PrivateKey: GeneratePrivate(KEY_SIZE),
	}
}

// LoadUser purse == public key for user converted to string
func LoadUser(purse string) *User {
	priv := ParsePrivate(purse)
	if priv == nil {
		return nil
	}

	return &User{
		PrivateKey: priv,
	}
}

func (u *User) purse() string {
	return StringPrivate(u.Private())
}

func (u *User) Address() string {
	return StringPublic(u.Public())
}

func (u *User) Private() *rsa.PrivateKey {
	return u.PrivateKey
}

func (u *User) Public() *rsa.PublicKey {
	return &(u.Private()).PublicKey
}

func Sign(private *rsa.PrivateKey, data []byte) []byte {
	signData, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, data, nil)
	if err != nil {
		return nil
	}

	return signData
}

func StringPublic(pub *rsa.PublicKey) string {
	return Base64Encode(x509.MarshalPKCS1PublicKey(pub))
}

func (u *User) Purse() string {
	return StringPrivate(u.Private())
}

func StringPrivate(pub *rsa.PrivateKey) string {
	return Base64Encode(x509.MarshalPKCS1PrivateKey(pub))
}

func ParsePrivate(data string) *rsa.PrivateKey {
	p, err := x509.ParsePKCS1PrivateKey(Base64Decode(data)) // todo
	if err != nil {
		return nil
	}

	return p
}

func GeneratePrivate(bits uint) *rsa.PrivateKey {
	p, err := rsa.GenerateKey(rand.Reader, int(bits))
	if err != nil {
		return nil
	}

	return p
}
