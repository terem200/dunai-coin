package network

import (
	"fmt"
	"strings"
	"time"
)

const (
	TO_UPPER = iota + 1
	TO_LOWER
)
const (
	ADDRESS = ":8080"
)

func main() {
	var (
		res = new(Package)
		msg = "Hello, World!"
	)
	go Listen(ADDRESS, handleServer)
	time.Sleep(500 * time.Millisecond)
	// send «Hello, World!»
	// receive «HELLO, WORLD!»
	res, _ = Send(ADDRESS, &Package{
		Option: TO_UPPER,
		Data:   msg,
	})
	fmt.Println(res.Data)
	// send «HELLO, WORLD!»
	// receive «hello, world!»
	res, _ = Send(ADDRESS, &Package{
		Option: TO_LOWER,
		Data:   res.Data,
	})
	fmt.Println(res.Data)
}
func handleServer(conn Conn, pack *Package) {
	Handle(TO_UPPER, conn, pack, handleToUpper)
	Handle(TO_LOWER, conn, pack, handleToLower)
}
func handleToUpper(pack *Package) string {
	return strings.ToUpper(pack.Data)
}
func handleToLower(pack *Package) string {
	return strings.ToLower(pack.Data)
}
