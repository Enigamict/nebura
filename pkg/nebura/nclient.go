package nebura

import (
	"encoding/binary"
	"log"
	"net"
)

type Prefix struct {
	Family    uint8
	PrefixLen uint8
	Prefix    net.IP
}

type RouteAdd struct {
	Prefix    Prefix
	srcPrefix Prefix
	index     uint8
}

func SendNclientMsg(c net.Conn, b *Update) error {

	var buf []byte
	buf = make([]byte, 3)

	binary.BigEndian.PutUint16(buf[0:2], 15)
	buf[2] = uint8(2)

	ApiHdr := &RouteAdd{
		Prefix: Prefix{
			Prefix:    b.NLRI.NLRI,
			PrefixLen: uint8(b.NLRI.Len),
		},
		srcPrefix: Prefix{
			Prefix:    b.Nexthop,
			PrefixLen: uint8(24),
		},
		index: uint8(40),
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

func NclientConect(b *Update) error {

	conn, err := net.Dial("unix", "/tmp/test.sock")

	if err != nil {
		log.Fatal(err)
	}

	err = SendNclientMsg(conn, b)

	if err != nil {
		log.Fatal(err)
	}

	return nil
}
