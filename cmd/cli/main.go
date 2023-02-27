package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
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

	binary.BigEndian.PutUint16(buf[0:2], 9)
	buf[2] = uint8(5)

	for i := 0; i < len("100ms"); i++ {
		buf = append(buf, []byte("100ms")[i])
	}

	s := fmt.Sprintf("%s", buf[3:8])
	index, _ := net.InterfaceByName("veth1")

	fmt.Printf("%s", s)
	fmt.Printf("%d", index.Index)
	fmt.Printf("%v", buf)

	buf = append(buf, byte(index.Index))
	_, err := c.Write(buf)
	if err != nil {
		return nil
	}

	return nil
}

func NeburaRead(c net.Conn) ([]byte, error) {
	buf := make([]byte, 12)

	_, err := io.ReadFull(c, buf)

	if err != nil {
		return nil, err
	}
	fmt.Printf("%x", buf)
	return buf, nil
}
func main() {

	//a, _ := config.ReadConfing("../../conf/static.yaml")
	//fmt.Printf("%v", a[0].Prefix.SrcPrefix)
	//for {
	//	p := nebura.PeerInit(65000, net.ParseIP("1.1.1.1").To4(), net.ParseIP("10.255.1.1"), "nebura")
	//	go p.Run()

	//	p1 := nebura.PeerInit(65001, net.ParseIP("1.1.1.2").To4(), net.ParseIP("10.255.2.2"), "nebura")
	//	p1.Run()
	//}
	var tcconfig string
	for i, v := range os.Args {
		fmt.Printf("args[%d] -> %s\n", i, v)
		tcconfig = v
	}

	c, err := config.TcConfing(tcconfig)
	if err != nil {
		log.Fatal(err)
	}

	n := nebura.NclientInit("TC")

	n.SendNclientTcNetem(c.Inter, c.Ms)

}
