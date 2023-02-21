package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

type Prefix struct {
	Family    uint8
	PrefixLen uint8
	Prefix    net.IP
}

type StaticRouteAdd struct {
	Prefix    Prefix
	srcPrefix Prefix
	index     uint8
}

type ApiType uint8

const (
	routeAdd ApiType = iota //0
	netlinkMode
)

const (
	protocol = "unix"
	sockAddr = "/tmp/test.sock"
)

type NapiHdr struct {
	Len  uint16
	Type ApiType
}

func Write(c net.Conn) error {

	var buf []byte
	buf = make([]byte, 3)

	binary.BigEndian.PutUint16(buf[0:2], 13)
	buf[2] = uint8(4)

	tmpbuf := make([]byte, 10, 10)
	buf = append(buf, tmpbuf...)
	_, err := c.Write(buf)

	if err != nil {
		log.Println(err)
	}
	return nil
}

func NeburaRead(c net.Conn) ([]byte, error) {
	buf := make([]byte, 12)

	_, err := io.ReadFull(c, buf)

	if err != nil {
		return nil, err
	}
	fmt.Printf("%v", buf)
	return buf, nil
}
func main() {

	conn, err := net.Dial(protocol, sockAddr)
	if err != nil {
		log.Fatal(err)
	}

	err = Write(conn)
	if err != nil {
		log.Fatal(err)
	}

	NeburaRead(conn)

}
