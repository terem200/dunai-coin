package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	bc "github.com/trempet/dunai-coin/blockchain"
	nt "github.com/trempet/dunai-coin/network"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	Filename    string
	Addresses   []string
	User        *bc.User
	Serve       string
	Chain       *bc.BlockChain
	Block       *bc.Block
	Mutex       sync.Mutex
	isMining    bool
	BreakMining = make(chan bool)
)

const (
	LOAD_SERVE_FLAG = "-serve:"
	NEW_CHAIN_FLAG  = "-newchain:"
	LOAD_CHAIN_FLAG = "-loadchain:"
	LOAD_ADDR_FLAG  = "-loadaddr:"
	NEW_USER_FLAG   = "-newuser:"
	LOAD_USER_FLAG  = "-loaduser:"

	COMMAND_EXIT  = "/exit"
	COMMAND_USER  = "/user"
	COMMAND_CHAIN = "/chain"
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
		addrStr     = ""
		userNewStr  = ""
		userLoadStr = ""
	)
	var (
		addrExist     = false
		userNewExist  = false
		userLoadExist = false
	)
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, LOAD_ADDR_FLAG):
			addrStr = strings.Replace(arg, LOAD_ADDR_FLAG, "", 1)
			addrExist = true
		case strings.HasPrefix(arg, NEW_USER_FLAG):
			userNewStr = strings.Replace(arg, NEW_USER_FLAG, "", 1)
			userNewExist = true
		case strings.HasPrefix(arg, LOAD_USER_FLAG):
			userLoadStr = strings.Replace(arg, LOAD_USER_FLAG, "", 1)
			userLoadExist = true
		}
	}

	if !(userNewExist || userLoadExist) || !addrExist {
		panic("failed: !(userNewExist || userLoadExist) || !addrExist")
	}

	err := json.Unmarshal([]byte(readFile(addrStr)), &Addresses)
	if err != nil {
		panic("failed: load addresses")
	}
	if len(Addresses) == 0 {
		panic("failed: len(Addresses) == 0")
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
}

func main() {
	handleClient()
}

func handleClient() {
	var (
		message string
		splited []string
	)
	for {
		message = inputString("> ")
		splited = strings.Split(message, " ")
		switch splited[0] {
		case COMMAND_EXIT:
			os.Exit(0)
		case COMMAND_USER:
			if len(splited) < 2 {
				fmt.Println("Undefined command for user\n")
				continue
			}
			switch splited[1] {
			case "address":
				userAddress()
			case "purse":
				userPurse()
			case "balance":
				userBalance()
			default:
				fmt.Println("command undefined\n")
			}
		case COMMAND_CHAIN:
			if len(splited) < 2 {
				fmt.Println("failed: len(chain) < 2\n")
				continue
			}
			switch splited[1] {
			case "print":
				chainPrint()
			case "tx":
				chainTX(splited[1:])
			case "balance":
				chainBalance(splited[1:])
			case "block":
				chainBlock(splited[1:])
			case "size":
				chainSize()
			default:
				fmt.Println("command undefined\n")
			}
		default:
			fmt.Println("command undefined\n")
		}
	}
}

func chainSize() {
	res, _ := nt.Send(Addresses[0], &nt.Package{
		Option: GET_CHAIN_SIZE,
	})
	if res == nil || res.Data == "" {
		fmt.Println("failed: getSize\n")
		return
	}
	fmt.Printf("Size: %s blocks\n\n", res.Data)
}

func chainBlock(splited []string) {
	if len(splited) != 2 {
		fmt.Println("failed: len(splited) != 2\n")
		return
	}
	num, err := strconv.Atoi(splited[1])
	if err != nil {
		fmt.Println("failed: strconv.Atoi(num)\n")
		return
	}
	res, _ := nt.Send(Addresses[0], &nt.Package{
		Option: GET_BLOCK,
		Data:   fmt.Sprintf("%d", num-1),
	})
	if res == nil || res.Data == "" {
		fmt.Println("failed: getBlock\n")
		return
	}
	fmt.Printf("[%d] => %s\n", num, res.Data)
}

func chainPrint() {
	for i := 0; ; i++ {
		res, _ := nt.Send(Addresses[0], &nt.Package{
			Option: GET_BLOCK,
			Data:   fmt.Sprintf("%d", i),
		})
		if res == nil || res.Data == "" {
			break
		}
		fmt.Printf("[%d] => %s\n", i+1, res.Data)
	}
	fmt.Println()
}

func chainTX(splited []string) {
	if len(splited) != 3 {
		fmt.Println("failed: len(splited) != 3\n")
		return
	}
	num, err := strconv.Atoi(splited[2])
	if err != nil {
		fmt.Println("failed: strconv.Atoi(num)\n")
		return
	}
	for _, addr := range Addresses {
		res, _ := nt.Send(addr, &nt.Package{
			Option: GET_L_HASH,
		})
		if res == nil {
			continue
		}
		tx := bc.NewTransaction(User, bc.Base64Decode(res.Data), splited[1], uint64(num))
		data, _ := bc.SerializeTX(tx)
		res, _ = nt.Send(addr, &nt.Package{
			Option: ADD_TX,
			Data:   data,
		})
		if res == nil {
			continue
		}
		if res.Data == "ok" {
			fmt.Printf("ok: (%s)\n", addr)
		} else {
			fmt.Printf("fail: (%s)\n", addr)
		}
	}
	fmt.Println()
}

func chainBalance(splited []string) {
	if len(splited) != 2 {
		fmt.Println("fail: len(splited) != 2\n")
		return
	}
	printBalance(splited[1])
}

func printBalance(useraddr string) {
	for _, addr := range Addresses {
		res, _ := nt.Send(addr, &nt.Package{
			Option: GET_BALANCE,
			Data:   useraddr,
		})
		if res == nil {
			continue
		}
		fmt.Printf("Balance (%s): %s coins\n", addr, res.Data)
	}
	fmt.Println()
}

func userAddress() {
	fmt.Println("Address:", User.Address(), "\n")
}

func userPurse() {
	fmt.Println("Purse:", User.Purse(), "\n")
}

func userBalance() {
	printBalance(User.Address())
}

func inputString(begin string) string {
	fmt.Print(begin)
	msg, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Replace(msg, "\n", "", 1)
}

func userNew(filename string) *bc.User {
	user := bc.NewUser()
	if user == nil {
		return nil
	}
	err := writeFile(filename, user.Purse())
	if err != nil {
		return nil
	}
	return user
}

func userLoad(filename string) *bc.User {
	priv := readFile(filename)
	if priv == "" {
		return nil
	}
	user := bc.LoadUser(priv)
	if user == nil {
		return nil
	}
	return user
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
