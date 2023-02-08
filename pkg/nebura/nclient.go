package nebura

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

const (
	protocol = "unix"
	sockAddr = "/tmp/test.sock"
)

func Write(c net.Conn) error {

	var buf []byte
	buf = make([]byte, 3)

	binary.BigEndian.PutUint16(buf[0:2], 1)
	buf[2] = uint8(1)

	ApiHdr := &StaticRouteAdd{
		Prefix: Prefix{
			Prefix:    net.ParseIP("8.7.6.7").To4(),
			PrefixLen: uint8(32),
		},
		srcPrefix: Prefix{
			Prefix:    net.ParseIP("192.168.64.6").To4(),
			PrefixLen: uint8(24),
		},
		index: uint8(2),
	}

	dstBlen := (int(ApiHdr.Prefix.PrefixLen) + 7) / 8
	buf = append(buf, ApiHdr.Prefix.PrefixLen)
	buf = append(buf, ApiHdr.Prefix.Prefix[:dstBlen]...)

	buf = append(buf, ApiHdr.srcPrefix.PrefixLen)
	buf = append(buf, ApiHdr.srcPrefix.Prefix[:dstBlen]...)
	buf = append(buf, ApiHdr.index)
	_, err := c.Write(buf)

	if err != nil {
		log.Println(err)
	}
	return nil
}

func NeburaClientRead(c net.Conn) ([]byte, error) {
	buf := make([]byte, 3)

	_, err := io.ReadFull(c, buf)

	if err != nil {
		return nil, err
	}

	return buf, nil
}
func main() {

	conn, err := net.Dial(protocol, sockAddr)
	if err != nil {
		log.Fatal(err)
	}

	func() {
		err = Write(conn)
		if err != nil {
			log.Fatal(err)
		}

	}()

	for {
		hdr, err := NeburaClientRead(conn)
		if err != nil {
			log.Println(err)
		}
		fmt.Printf("%v", hdr)
	}

}
