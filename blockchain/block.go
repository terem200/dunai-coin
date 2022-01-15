package blockchain

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"time"
)

type Block struct {
	CurrHash     []byte
	PrevHash     []byte
	Nonce        uint64
	Difficulty   uint8
	Miner        string
	Signature    []byte
	TimeStamp    string
	Transactions []Transaction
	Mapping      map[string]uint64
}

const (
	DEBUG = true
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func NewBlock(miner string, prevHash []byte) *Block {
	return &Block{
		Difficulty: DIFFICULTY,
		PrevHash:   prevHash,
		Miner:      miner,
		Mapping:    map[string]uint64{},
	}
}

func (block *Block) Accept(chain *BlockChain, user *User, ch chan bool) error {
	if !block.TransactionsIsValid(chain) {
		return errors.New("transactions is not valid")
	}

	err := block.AddTransaction(
		chain,
		&Transaction{
			RandomBytes: GenerateRandBytes(RANDOM_BYTES),
			Sender:      STORAGE_CHAIN,
			Receiver:    user.Address(),
			Value:       STORAGE_REWARD,
		})
	if err != nil {
		return err
	}
	block.TimeStamp = time.Now().Format(time.RFC3339)
	block.CurrHash = block.hash()
	block.Signature = block.sign(user.Private())
	block.Nonce = block.proof(ch)

	return nil
}

func (block *Block) TransactionsIsValid(chain *BlockChain) bool {
	length := len(block.Transactions)
	plusStorage := 0

	for _, tx := range block.Transactions {
		if tx.Sender == STORAGE_CHAIN {
			plusStorage = 1
			break
		}
	}

	if length == 0 || length > (TXS_LIMIT+plusStorage) {
		return false
	}
	for i := 0; i < length-1; i++ {
		for j := i + 1; j < length; j++ {
			if bytes.Equal(block.Transactions[i].RandomBytes, block.Transactions[j].RandomBytes) {
				return false
			}
			if block.Transactions[i].Sender == STORAGE_CHAIN &&
				block.Transactions[j].Sender == STORAGE_CHAIN {
				return false
			}
		}
	}

	for i := 0; i < length; i++ {
		tx := block.Transactions[i]
		if tx.Sender == STORAGE_CHAIN {
			if tx.Receiver != block.Miner || tx.Value != STORAGE_REWARD {
				return false
			}
		} else {
			if !tx.isHashValid() {
				return false
			}
			if !tx.isSignValid() {
				return false
			}
		}
		if !block.isValidBalance(chain, tx.Sender) {
			return false
		}

		if !block.isValidBalance(chain, tx.Receiver) {
			return false
		}
	}

	return true
}

func (block *Block) hash() []byte {
	var tempHash []byte
	for _, tx := range block.Transactions {
		tempHash = HashSum(bytes.Join(
			[][]byte{
				tempHash,
				tx.CurrHash,
			},
			[]byte{},
		))
	}
	var list []string
	for hash := range block.Mapping {
		list = append(list, hash)
	}
	sort.Strings(list)
	for _, hash := range list {
		tempHash = HashSum(bytes.Join(
			[][]byte{
				tempHash,
				[]byte(hash),
				ToBytes(block.Mapping[hash]),
			},
			[]byte{},
		))
	}
	return HashSum(bytes.Join(
		[][]byte{
			tempHash,
			ToBytes(uint64(block.Difficulty)),
			block.PrevHash,
			[]byte(block.Miner),
			[]byte(block.TimeStamp),
		},
		[]byte{},
	))
}

func (block *Block) sign(private *rsa.PrivateKey) []byte {
	return Sign(private, block.CurrHash)
}

func (block *Block) proof(ch chan bool) uint64 {
	return ProofOfWork(block.CurrHash, block.Difficulty, ch)
}

func (block *Block) addBalance(ch *BlockChain, receiver string, value uint64) {
	var balanceInChain uint64
	if v, ok := block.Mapping[receiver]; ok {
		balanceInChain = v
	} else {
		balanceInChain = ch.Balance(receiver)
	}

	block.Mapping[receiver] = balanceInChain + value
}
func (block *Block) AddTransaction(chain *BlockChain, tx *Transaction) error {
	if tx == nil {
		return errors.New("transaction is null")
	}

	if tx.Value == 0 {
		return errors.New("transaction value is 0")
	}

	if len(block.Transactions) == TXS_LIMIT && tx.Sender != STORAGE_CHAIN {
		return errors.New("len tx = limit")
	}

	var balanceInChain uint64
	balanceInTx := tx.Value + tx.ToStorage

	if value, ok := block.Mapping[tx.Sender]; ok {
		balanceInChain = value
	} else {
		balanceInChain = chain.Balance(tx.Sender)
	}
	if tx.Value > START_PERCENT && tx.ToStorage != STORAGE_REWARD {
		return errors.New("storage reward missing")
	}
	if balanceInTx > balanceInChain {
		return errors.New("balance in transaction more than balance in chain")
	}

	block.Mapping[tx.Sender] = balanceInChain - balanceInTx
	block.addBalance(chain, tx.Receiver, tx.Value)
	block.addBalance(chain, STORAGE_CHAIN, tx.ToStorage)
	block.Transactions = append(block.Transactions, *tx)
	return nil
}

func (block *Block) isValidBalance(chain *BlockChain, address string) bool {
	if _, ok := block.Mapping[address]; ok {
		return false
	}
	length := len(block.Transactions)
	balanceInChain := chain.Balance(address)
	balanceSubBlock := uint64(0)
	balanceAddBlock := uint64(0)

	for i := 0; i < length; i++ {
		tx := block.Transactions[i]
		if tx.Sender == address {
			balanceSubBlock = tx.Value + tx.ToStorage
		}

		if tx.Receiver == address {
			balanceAddBlock = tx.Value
		}

		if tx.Receiver == address && STORAGE_CHAIN == address {
			balanceAddBlock += tx.ToStorage
		}

	}

	if (balanceInChain + balanceAddBlock - balanceSubBlock) != block.Mapping[address] {
		return false
	}

	return true
}

func SerializeBlock(b *Block) string {
	jstr, err := json.MarshalIndent(*b, "", "\t")
	if err != nil {
		return ""
	}

	return string(jstr)
}

func (block *Block) IsValid(chain *BlockChain) bool {
	switch {
	case block == nil:
		return false
	case block.Difficulty != DIFFICULTY:
		return false
	case !block.isValidHash(chain, chain.Size()):
		return false
	case !block.isValidSign():
		return false
	case !block.isValidProof():
		return false
	case !block.isValidMapping():
		return false
	case !block.isValidTime(chain, chain.Size()):
		return false
	case !block.TransactionsIsValid(chain):
		return false
	default:
		return true
	}
}

func (block *Block) isValidHash(ch *BlockChain, idx uint64) bool {
	if !bytes.Equal(block.hash(), block.CurrHash) {
		return false
	}
	var id uint64
	row := ch.DB.QueryRow("SELECT Id FROM Blockchain WHERE Hash=$1", Base64Encode(block.PrevHash))
	row.Scan(&id)
	return id == idx
}

func (block *Block) isValidSign() bool {
	return Verify(ParsePublic(block.Miner), block.CurrHash, block.Signature) == nil
}

func (block *Block) isValidProof() bool {
	const max = 255
	intHash := big.NewInt(1)
	target := big.NewInt(1)
	hash := HashSum(bytes.Join(
		[][]byte{
			block.hash(),
			ToBytes(block.Nonce),
		},
		[]byte{},
	))
	intHash.SetBytes(hash)
	target.Lsh(target, 255-uint(block.Difficulty))

	if intHash.Cmp(target) == -1 {
		return true
	}

	return false
}

func (block *Block) isValidMapping() bool {
	for addr := range block.Mapping {
		if addr == STORAGE_CHAIN {
			continue
		}
		flag := false
		for _, tx := range block.Transactions {
			if tx.Receiver == addr || tx.Sender == addr {
				flag = true
				break
			}
		}
		if !flag {
			return false
		}
	}

	return true
}

func (block *Block) isValidTime(chain *BlockChain, idx uint64) bool {
	btime, err := time.Parse(time.RFC3339, block.TimeStamp)
	if err != nil {
		return false
	}

	diff := time.Now().Sub(btime)
	if diff < 0 {
		return false
	}

	var sblock string
	row := chain.DB.QueryRow("SELECT Block FROM Blockchain WHERE Hash=$1", Base64Encode(block.PrevHash))
	row.Scan(&sblock)

	lastBlock, err := DeserializeBlock(sblock)
	if err != nil {
		return false
	}

	ltime, err := time.Parse(time.RFC3339, lastBlock.TimeStamp)
	if err != nil {
		return false
	}

	diff = btime.Sub(ltime)
	return diff > 0

}

func DeserializeBlock(data string) (*Block, error) {
	var b Block
	err := json.Unmarshal([]byte(data), &b)
	if err != nil {
		return nil, err
	}

	return &b, err
}

func ProofOfWork(blockHash []byte, diff uint8, ch chan bool) (nonce uint64) {
	const max uint8 = 255 // check maybe 256
	var (
		target  = big.NewInt(1)
		intHash = big.NewInt(1)
		hash    []byte
	)
	nonce = uint64(rand.Intn(math.MaxUint32))
	target.Lsh(target, uint(max-diff))

	for nonce < math.MaxUint64 {
		select {
		case <-ch:
			if DEBUG {
				fmt.Println()
			}
			return nonce
		default:
			hash = HashSum(bytes.Join(
				[][]byte{
					blockHash,
					ToBytes(nonce),
				},
				[]byte{},
			))
			if DEBUG {
				fmt.Printf("Mining: %s", Base64Encode(hash))
			}
			intHash.SetBytes(hash)
			if intHash.Cmp(target) == -1 {
				fmt.Println()
				return nonce
			}
		}
		nonce++
	}

	return nonce
}
