package blockchain

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	_ "github.com/mattn/go-sqlite3"
)

type Transaction struct {
	RandomBytes []byte
	PrevBlock   []byte
	Sender      string
	Receiver    string
	Value       uint64
	ToStorage   uint64
	CurrHash    []byte
	Signature   []byte
}

func NewTransaction(user *User, lastHash []byte, receiver string, value uint64) *Transaction {
	tx := &Transaction{
		RandomBytes: GenerateRandBytes(RANDOM_BYTES),
		PrevBlock:   lastHash,
		Sender:      user.Address(),
		Receiver:    receiver,
		Value:       value,
	}
	if value > START_PERCENT {
		tx.ToStorage = STORAGE_REWARD
	}

	tx.CurrHash = tx.hash()
	tx.Signature = tx.sign(user.Private())

	return tx
}

func (tx *Transaction) hash() []byte {
	return HashSum(bytes.Join(
		[][]byte{
			tx.RandomBytes,
			tx.PrevBlock,
			[]byte(tx.Sender),
			[]byte(tx.Receiver),
			ToBytes(tx.Value),
			ToBytes(tx.ToStorage),
		},
		[]byte{},
	))
}

func (tx *Transaction) sign(private *rsa.PrivateKey) []byte {
	return Sign(private, tx.CurrHash)
}

func (tx *Transaction) isHashValid() bool {
	return bytes.Equal(tx.hash(), tx.CurrHash)
}

func (tx *Transaction) isSignValid() bool {
	return Verify(ParsePublic(tx.Sender), tx.CurrHash, tx.Signature) == nil
}

func Verify(pub *rsa.PublicKey, data, sign []byte) error {
	return rsa.VerifyPSS(pub, crypto.SHA256, data, sign, nil)
}

func ParsePublic(pubData string) *rsa.PublicKey {
	pub, err := x509.ParsePKCS1PublicKey(Base64Decode(pubData))
	if err != nil {
		return nil
	}

	return pub
}

func SerializeTX(p *Transaction) (string, error) {
	jstr, err := json.MarshalIndent(*p, "", "\t")
	if err != nil {
		return "", err
	}

	return string(jstr), err
}

func DeserializeTX(data string) (*Transaction, error) {
	var t Transaction
	err := json.Unmarshal([]byte(data), &t)
	if err != nil {
		return nil, err
	}

	return &t, err
}
