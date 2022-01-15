package main

import (
	"fmt"
	"github.com/trempet/dunai-coin/network"
	"strings"
	"time"
)

const (
	TO_UPPER = iota + 1
	TO_LOWWER
)

const (
	ADDRESS = ":8080"
)

func main() {
	go network.Listen(ADDRESS, handleServer)
	time.Sleep(1 * time.Second)

	res, _ := network.Send(ADDRESS, &network.Package{
		Option: TO_UPPER,
		Data:   "Hello, World",
	})

	fmt.Println(res.Data)

	res2, _ := network.Send(ADDRESS, &network.Package{
		Option: TO_LOWWER,
		Data:   "Hello, World",
	})

	fmt.Println(res2.Data)
}

func handleServer(conn network.Conn, p *network.Package) {
	network.Handle(TO_UPPER, conn, p, handleToUpper)
	network.Handle(TO_LOWWER, conn, p, handleToLower)
}

func handleToUpper(p *network.Package) string {
	return strings.ToUpper(p.Data)
}

func handleToLower(p *network.Package) string {
	return strings.ToLower(p.Data)
}
