package nebura

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

type Body interface {
	writeTo() ([]byte, error)
}

type ApiHeader struct {
	Len  uint16
	Type uint8
	Body Body
}

type Prefix struct {
	PrefixLen uint8
	Prefix    net.IP
}

type NclientRouteAdd struct {
	Nexthop Prefix
	NLRI    Prefix
}

type NclientBgpRibFind struct {
	NLRI      Prefix
	RouteType uint8
}

type NclientIPv6RouteAdd struct {
	Nexthop Prefix
	NLRI    Prefix
}

type NclientTcNetem struct {
	rate  string
	inter string
}

type Nclient struct {
	Type string
	Conn net.Conn
}

func (n *NclientRouteAdd) writeTo() ([]byte, error) {

	var buf []byte

	dstBlen := (int(n.NLRI.PrefixLen) + 7) / 8
	buf = append(buf, n.NLRI.PrefixLen)
	buf = append(buf, n.NLRI.Prefix[:dstBlen]...)

	buf = append(buf, n.Nexthop.PrefixLen)
	buf = append(buf, n.Nexthop.Prefix[:dstBlen]...)

	return buf, nil
}

func (n *NclientIPv6RouteAdd) writeTo() ([]byte, error) {

	var buf []byte
	buf = append(buf, n.NLRI.Prefix[:]...)
	buf = append(buf, n.NLRI.PrefixLen)
	fmt.Printf("ipv6 buf:%v\n", net.IP(buf).To16())

	return buf, nil
}

func (n *NclientTcNetem) writeTo() ([]byte, error) {

	var buf []byte

	for i := 0; i < len(n.rate); i++ {
		buf = append(buf, []byte(n.rate)[i])
	}

	index, _ := net.InterfaceByName(n.inter)
	buf = append(buf, byte(index.Index))
	return buf, nil
}

func (n *NclientBgpRibFind) writeTo() ([]byte, error) {

	var buf []byte
	buf[0] = n.RouteType
	return buf, nil
}

func (api *ApiHeader) writeTo() ([]byte, error) {
	var buf []byte
	buf = make([]byte, 3)
	binary.BigEndian.PutUint16(buf[0:2], NeburaHdrSize) // 可変になる
	buf[2] = uint8(api.Type)

	hdr, err := api.Body.writeTo()

	if err != nil {
		return nil, err
	}

	return append(buf, hdr...), nil
}

//func (n *Nclient) readNclietMsg() error {
//
//	for {
//		log.Printf("Read...\n")
//		var header [3]byte
//		_, err := io.ReadFull(n.Conn, header[:])
//
//		if err != nil {
//			log.Printf("err read")
//			return nil
//		}
//	}
//}

func (n *Nclient) sendNclientAPI(rtype uint8, body Body) error {
	api := &ApiHeader{
		Len:  NeburaHdrSize,
		Type: rtype,
		Body: body,
	}

	buf, _ := api.writeTo()

	log.Printf("Send buf %v...\n", buf)
	n.Conn.Write(buf)
	return nil
}

func (n *Nclient) SendNclientIPv4RouteAdd(prefix net.IP, nexthop net.IP, len uint8) error {

	body := &NclientRouteAdd{
		Nexthop: Prefix{
			Prefix:    nexthop,
			PrefixLen: 24,
		},
		NLRI: Prefix{
			Prefix:    prefix,
			PrefixLen: len,
		},
	}

	NeburaHdrSize = 13

	n.sendNclientAPI(2, body)
	return nil

}

func (n *Nclient) SendNclientIPv6RouteAdd(prefix net.IP, nexthop net.IP, len uint8) error {

	body := &NclientRouteAdd{
		Nexthop: Prefix{
			Prefix: nexthop,
		},
		NLRI: Prefix{
			Prefix:    prefix.To16(),
			PrefixLen: len,
		},
	}

	NeburaHdrSize = 20
	fmt.Printf("body :%s", hex.Dump(body.NLRI.Prefix))
	n.sendNclientAPI(3, body)
	return nil

}

func (n *Nclient) SendNclientTcNetem(inter string, rate string) error {

	body := &NclientTcNetem{
		inter: inter,
		rate:  rate,
	}

	NeburaHdrSize = 9

	n.sendNclientAPI(5, body)
	return nil

}

func NclientInit(ntype string) *Nclient {
	conn, err := net.Dial("unix", "/tmp/test.sock")

	if err != nil {
		log.Fatal(err)
	}

	n := &Nclient{
		Type: ntype,
		Conn: conn,
	}

	return n
}
