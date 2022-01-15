package network

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type Listener net.Listener
type Conn net.Conn

type Package struct {
	// action
	Option int
	// data
	Data string
}

const (
	END_BYTES   = "\000\005\007\001\001\007\005\000"
	WAIT_TIME   = 5
	D_MAX_SIZE  = 2 << 20 // (2^20)*2 = 2MiB
	BUFFER_SIZE = 4 << 10 // (2^10)*4 = 4KiB
)

// Send

func Send(addr string, p *Package) (*Package, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("send func, %s ", err.Error())
	}
	defer conn.Close()

	serPack, _ := SerializePackage(p)
	conn.Write([]byte(serPack + END_BYTES))

	ch := make(chan bool)
	res := new(Package)

	go func() {
		res = readPackage(conn)
		ch <- true
	}()

	select {
	case <-ch:
	case <-time.After(WAIT_TIME * time.Second):
	}

	return res, nil
}

func SerializePackage(p *Package) (string, error) {
	jstr, err := json.MarshalIndent(*p, "", "\t")
	if err != nil {
		return "", err
	}

	return string(jstr), err
}

func DeserializePackage(data string) (*Package, error) {
	var p Package
	err := json.Unmarshal([]byte(data), &p)
	if err != nil {
		return nil, err
	}

	return &p, err
}

func readPackage(conn net.Conn) *Package {
	buff := make([]byte, BUFFER_SIZE)
	size := uint64(0)
	var data string

	for {
		length, err := conn.Read(buff)
		if err != nil {
			return nil
		}

		size += uint64(length)
		if size > D_MAX_SIZE {
			return nil
		}

		data += string(buff[:length])
		if strings.Contains(data, END_BYTES) {
			data = strings.Split(data, END_BYTES)[0]
			break
		}
	}
	p, _ := DeserializePackage(data)
	return p
}

// Send

func Listen(addr string, handler func(Conn, *Package)) Listener {
	splitted := strings.Split(addr, ":")
	if len(splitted) != 2 {
		return nil
	}
	listener, err := net.Listen("tcp", "0.0.0.0:"+splitted[1])
	if err != nil {
		return nil
	}
	go serve(listener, handler)
	return Listener(listener)
}

func serve(listener Listener, handler func(Conn, *Package)) {
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		go handleConn(conn, handler)
	}
}

func handleConn(c Conn, handler func(Conn, *Package)) {
	defer c.Close()
	pack := readPackage(c)
	if pack == nil {
		return
	}
	handler(Conn(c), pack)
}

func Handle(option int, c Conn, p *Package, handler func(*Package) string) bool {
	if p.Option != option {
		return false
	}
	serialized, _ := SerializePackage(&Package{
		Option: option,
		Data:   handler(p),
	})
	c.Write([]byte(serialized + END_BYTES))
	return true
}
