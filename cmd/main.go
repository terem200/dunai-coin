package main

import (
	"fmt"
	bc "github.com/trempet/dunai-coin/blockchain"
)

const (
	DB_NAME = "testdb"
)

func main() {
	miner := bc.NewUser()
	err := bc.NewChain(DB_NAME, miner.Address())
	if err != nil {
		fmt.Println(err.Error())
	}
	chain := bc.LoadChain(DB_NAME)

	for i := 0; i < 3; i++ {
		block := bc.NewBlock(miner.Address(), chain.LastHash())
		err := block.AddTransaction(chain, bc.NewTransaction(miner, chain.LastHash(), "aaa", 1))
		if err != nil {
			fmt.Println(err.Error())
		}
		err = block.AddTransaction(chain, bc.NewTransaction(miner, chain.LastHash(), "bbb", 1))
		if err != nil {
			fmt.Println(err.Error())
		}
		err = block.Accept(chain, miner, make(chan bool))
		if err != nil {
			fmt.Println(err.Error())
		}
		chain.AddBlock(block)
	}

	var sblock string
	rows, err := chain.DB.Query("SELECT Block FROM Blockchain")
	if err != nil {
		fmt.Println(err.Error())
	}
	for rows.Next() {
		rows.Scan(&sblock)
		fmt.Println(sblock)
	}

}
