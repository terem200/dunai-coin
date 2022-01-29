package main

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/trempet/dunai-coin/blockchain"
	"github.com/trempet/dunai-coin/network"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	Filename    string
	Addresses   []string
	User        *blockchain.User
	Serve       string
	Chain       *blockchain.BlockChain
	Block       *blockchain.Block
	Mutex       sync.Mutex
	isMining    bool
	BreakMining = make(chan bool)
)

const (
	LOAD_SERVE_FLAG = "-serve"
	NEW_CHAIN_FLAG  = "-newchain"
	LOAD_CHAIN_FLAG = "-loadchain"
	LOAD_ADDR_FLAG  = "-loadaddr"
	NEW_USER_FLAG   = "-newuser"
	LOAD_USER_FLAG  = "-loaduser"

	COMMAND_EXIT  = "/exit"
	COMMAND_USER  = "/user"
	COMMAND_CHAIN = "/chain"

	SEPARATOR = "_SEPARATOR_"
)

const (
	ADD_BLOCK = iota + 1
	ADD_TX
	GET_BLOCK
	GET_L_HASH
	GET_BALANCE
	GET_CHAIN_SIZE
)

func init() {
	if len(os.Args) < 2 {
		panic("failed: len(os.Args) < 2")
	}
	var (
		serveStr     = ""
		addrStr      = ""
		userNewStr   = ""
		userLoadStr  = ""
		chainNewStr  = ""
		chainLoadStr = ""
	)
	var (
		serveExist     = false
		addrExist      = false
		userNewExist   = false
		userLoadExist  = false
		chainNewExist  = false
		chainLoadExist = false
	)
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, "-serve:"):
			serveStr = strings.Replace(arg, "-serve:", "", 1)
			serveExist = true
		case strings.HasPrefix(arg, "-loadaddr:"):
			addrStr = strings.Replace(arg, "-loadaddr:", "", 1)
			addrExist = true
		case strings.HasPrefix(arg, "-newuser:"):
			userNewStr = strings.Replace(arg, "-newuser:", "", 1)
			userNewExist = true
		case strings.HasPrefix(arg, "-loaduser:"):
			userLoadStr = strings.Replace(arg, "-loaduser:", "", 1)
			userLoadExist = true
		case strings.HasPrefix(arg, "-newchain:"):
			chainNewStr = strings.Replace(arg, "-newchain:", "", 1)
			chainNewExist = true
		case strings.HasPrefix(arg, "-loadchain:"):
			chainLoadStr = strings.Replace(arg, "-loadchain:", "", 1)
			chainLoadExist = true
		}
	}

	if !(userNewExist || userLoadExist) || !(chainNewExist || chainLoadExist) ||
		!serveExist || !addrExist {
		panic("failed: !(userNewExist || userLoadExist)" +
			"|| !(chainNewExist || chainLoadExist) || !serveExist || !addrExist")
	}

	Serve = serveStr

	var addresses []string
	err := json.Unmarshal([]byte(readFile(addrStr)), &addresses)
	if err != nil {
		panic("failed: load addresses")
	}

	var mapaddr = make(map[string]bool)
	for _, addr := range addresses {
		if addr == Serve {
			continue
		}
		if _, ok := mapaddr[addr]; ok {
			continue
		}
		mapaddr[addr] = true
		Addresses = append(Addresses, addr)
	}

	if userNewExist {
		User = userNew(userNewStr)
	}
	if userLoadExist {
		User = userLoad(userLoadStr)
	}
	if User == nil {
		panic("failed: load user")
	}

	if chainNewExist {
		Filename = chainNewStr
		Chain = chainNew(chainNewStr)
	}
	if chainLoadExist {
		Filename = chainLoadStr
		Chain = chainLoad(chainLoadStr)
	}
	if Chain == nil {
		panic("failed: load chain")
	}

	Block = blockchain.NewBlock(User.Address(), Chain.LastHash())
}

func readFile(filename string) string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return ""
	}

	return string(data)
}
func writeFile(filename, data string) error {
	return ioutil.WriteFile(filename, []byte(data), 0644)
}

func userNew(filename string) *blockchain.User {
	user := blockchain.NewUser()
	if user == nil {
		return nil
	}
	err := writeFile(filename, user.Purse())
	if err != nil {
		return nil
	}
	return user
}

func userLoad(filename string) *blockchain.User {
	priv := readFile(filename)
	if priv == "" {
		return nil
	}
	user := blockchain.LoadUser(priv)
	if user == nil {
		return nil
	}
	return user
}

func chainNew(filename string) *blockchain.BlockChain {
	err := blockchain.NewChain(filename, User.Address())
	if err != nil {
		return nil
	}

	return blockchain.LoadChain(filename)
}

func chainLoad(filename string) *blockchain.BlockChain {
	chain := blockchain.LoadChain(filename)
	return chain
}

func handleServer(conn network.Conn, pack *network.Package) {
	network.Handle(ADD_BLOCK, conn, pack, addBlock)
	network.Handle(ADD_TX, conn, pack, addTransaction)
	network.Handle(GET_BLOCK, conn, pack, getBlock)
	network.Handle(GET_L_HASH, conn, pack, getLastHash)
	network.Handle(GET_BALANCE, conn, pack, getBalance)
}

func addBlock(pack *network.Package) string {
	splited := strings.Split(pack.Data, SEPARATOR)
	if len(splited) != 3 {
		return "fail"
	}
	block, _ := blockchain.DeserializeBlock(splited[2])
	if !block.IsValid(Chain, Chain.Size()) {
		currSize := Chain.Size()
		num, err := strconv.Atoi(splited[1])
		if err != nil {
			return "fail"
		}
		if currSize < uint64(num) {
			go compareChains(splited[0], uint64(num))
			return "ok "
		}
		return "fail"
	}
	Mutex.Lock()
	Chain.AddBlock(block)
	Block = blockchain.NewBlock(User.Address(), Chain.LastHash())
	Mutex.Unlock()
	if isMining {
		BreakMining <- true
		isMining = false
	}
	return "ok"
}

func addTransaction(pack *network.Package) string {
	var tx, _ = blockchain.DeserializeTX(pack.Data)
	if tx == nil || len(Block.Transactions) == blockchain.TXS_LIMIT {
		return "fail"
	}
	Mutex.Lock()
	err := Block.AddTransaction(Chain, tx)
	Mutex.Unlock()
	if err != nil {
		return "fail"
	}
	if len(Block.Transactions) == blockchain.TXS_LIMIT {
		go func() {
			Mutex.Lock()
			block := *Block
			isMining = true
			Mutex.Unlock()
			res := (&block).Accept(Chain, User, BreakMining)
			Mutex.Lock()
			isMining = false
			if res == nil && bytes.Equal(block.PrevHash, Block.PrevHash) {
				Chain.AddBlock(&block)
				pushBlockToNet(&block)
			}
			Block = blockchain.NewBlock(User.Address(), Chain.LastHash())
			Mutex.Unlock()
		}()
	}
	return "ok"
}

func getBlock(pack *network.Package) string {
	num, err := strconv.Atoi(pack.Data)
	if err != nil {
		return ""
	}
	size := Chain.Size()
	if uint64(num) < size {
		return selectBlock(Chain, num)
	}
	return ""
}

func getLastHash(pack *network.Package) string {
	return blockchain.Base64Encode(Chain.LastHash())
}

func getBalance(pack *network.Package) string {
	return fmt.Sprintf("%d", Chain.Balance(pack.Data, Chain.Size()))
}

func getChainSize(pack *network.Package) string {
	return fmt.Sprintf("%d", Chain.Size())
}

func compareChains(address string, num uint64) {
	filename := "temp_" + hex.EncodeToString(blockchain.GenerateRandBytes(8))
	file, err := os.Create(filename)
	if err != nil {
		return
	}
	file.Close()
	defer func() {
		os.Remove(filename)
	}()
	res, _ := network.Send(address, &network.Package{
		Option: GET_BLOCK,
		Data:   fmt.Sprintf("%d", 0),
	})
	if res == nil {
		return
	}
	genesis, _ := blockchain.DeserializeBlock(res.Data)
	if genesis == nil {
		return
	}
	if !bytes.Equal(genesis.CurrHash, hashBlock(genesis)) {
		return
	}
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return
	}
	defer db.Close()
	_, err = db.Exec(blockchain.CREATE_TABLE)
	chain := &blockchain.BlockChain{
		DB: db,
	}
	chain.AddBlock(genesis)
	for i := uint64(1); i < num; i++ {
		res, _ := network.Send(address, &network.Package{
			Option: GET_BLOCK,
			Data:   fmt.Sprintf("%d", i),
		})
		if res == nil {
			return
		}
		block, _ := blockchain.DeserializeBlock(res.Data)
		if block == nil {
			return
		}
		if !block.IsValid(chain, i) {
			return
		}
		chain.AddBlock(block)
	}
	Mutex.Lock()
	Chain.DB.Close()
	os.Remove(Filename)
	copyFile(filename, Filename)
	Chain = blockchain.LoadChain(Filename)
	Block = blockchain.NewBlock(User.Address(), Chain.LastHash())
	Mutex.Unlock()
	if isMining {
		BreakMining <- true
		isMining = false
	}
}

func pushBlockToNet(block *blockchain.Block) {
	var (
		sblock = blockchain.SerializeBlock(block)
		msg    = Serve + SEPARATOR + fmt.Sprintf("%d", Chain.Size()) + SEPARATOR + sblock
	)
	for _, addr := range Addresses {
		go network.Send(addr, &network.Package{
			Option: ADD_BLOCK,
			Data:   msg,
		})
	}
}
func selectBlock(chain *blockchain.BlockChain, i int) string {
	var block string
	row := chain.DB.QueryRow("SELECT Block FROM Blockchain WHERE Id=$1", i+1)
	row.Scan(&block)
	return block
}

func hashBlock(block *blockchain.Block) []byte {
	var tempHash []byte
	for _, tx := range block.Transactions {
		tempHash = blockchain.HashSum(bytes.Join(
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
		tempHash = blockchain.HashSum(bytes.Join(
			[][]byte{
				tempHash,
				[]byte(hash),
				blockchain.ToBytes(block.Mapping[hash]),
			},
			[]byte{},
		))
	}
	return blockchain.HashSum(bytes.Join(
		[][]byte{
			tempHash,
			blockchain.ToBytes(uint64(block.Difficulty)),
			block.PrevHash,
			[]byte(block.Miner),
			[]byte(block.TimeStamp),
		},
		[]byte{},
	))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func main() {
	network.Listen(Serve, handleServer)
	for {
		fmt.Scanln()
	}
}
