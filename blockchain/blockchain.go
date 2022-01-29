package blockchain

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"time"
)

const (
	CREATE_TABLE = "CREATE TABLE Blockchain(" +
		"Id INTEGER PRIMARY KEY AUTOINCREMENT," +
		"Hash VARCHAR(44) UNIQUE," + // len(base64(sha256(data))) = 44
		"Block TEXT)"
)

const (
	GENESIS_BLOCK  = "GENESIS-BLOCK"
	STORAGE_VALUE  = 100
	GENESIS_REWARD = 100
	STORAGE_CHAIN  = "STORAGE-CHAIN"

	DIFFICULTY     = 20
	RANDOM_BYTES   = 32
	START_PERCENT  = 10
	STORAGE_REWARD = 1
	TXS_LIMIT      = 2
)

type BlockChain struct {
	DB    *sql.DB
	index uint64
}

func NewChain(filename, receiver string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	file.Close()
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(CREATE_TABLE)
	if err != nil {
		return err
	}
	chain := &BlockChain{
		DB: db,
	}
	genesis := &Block{
		PrevHash:  []byte(GENESIS_BLOCK),
		Mapping:   make(map[string]uint64),
		Miner:     receiver,
		TimeStamp: time.Now().Format(time.RFC3339),
	}
	genesis.Mapping[STORAGE_CHAIN] = STORAGE_VALUE
	genesis.Mapping[receiver] = GENESIS_REWARD
	genesis.CurrHash = genesis.hash()
	chain.AddBlock(genesis)
	return nil
}

func LoadChain(filename string) *BlockChain {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil
	}

	chain := &BlockChain{
		DB: db,
	}
	chain.index = chain.Size()
	return chain
}

func (ch *BlockChain) AddBlock(b *Block) {
	ch.index += 1
	_, err := ch.DB.Exec("INSERT INTO Blockchain (Hash, Block) VALUES($1, $2)",
		Base64Encode(b.CurrHash),
		SerializeBlock(b))
	if err != nil {
		return
	}
}

func (ch *BlockChain) Size() uint64 {
	var index uint64
	row := ch.DB.QueryRow("SELECT Id from Blockchain ORDER BY Id DESC")
	row.Scan(&index)
	return index
}

func Base64Encode(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

func Base64Decode(data string) []byte {
	res, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return res
}

func (ch *BlockChain) Balance(addr string, size uint64) uint64 {
	var (
		sblock  string
		block   *Block
		balance uint64
	)
	rows, err := ch.DB.Query("SELECT Block FROM BlockChain WHERE Id <= $1 ORDER BY Id DESC", size)
	if err != nil {
		return balance
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&sblock)
		block, _ = DeserializeBlock(sblock)
		if value, ok := block.Mapping[addr]; ok {
			balance = value
			break
		}
	}
	return balance
}

func (ch *BlockChain) LastHash() []byte {
	var hash string
	row := ch.DB.QueryRow("SELECT Hash FROM Blockchain ORDER BY Id DESC ")
	row.Scan(&hash)
	return Base64Decode(hash)
}

func HashSum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func ToBytes(num uint64) []byte {
	var data = new(bytes.Buffer)
	err := binary.Write(data, binary.BigEndian, num)
	if err != nil {
		return nil
	}

	return data.Bytes()
}

func GenerateRandBytes(max uint) []byte {
	var slice = make([]byte, max)

	_, err := rand.Read(slice)
	if err != nil {
		return nil
	}

	return slice
}
