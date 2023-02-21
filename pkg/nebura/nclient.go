package nebura

import (
	"encoding/binary"
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

	n.sendNclientAPI(2, body)
	return nil

}

func (n *Nclient) SendNclientIPv6RouteAdd(prefix net.IP, nexthop net.IP, len uint8) error {

	body := &NclientRouteAdd{
		Nexthop: Prefix{
			Prefix: nexthop,
		},
		NLRI: Prefix{
			Prefix:    prefix,
			PrefixLen: len,
		},
	}

	n.sendNclientAPI(3, body)
	return nil

}

func NclientInit() *Nclient {
	conn, err := net.Dial("unix", "/tmp/test.sock")

	if err != nil {
		log.Fatal(err)
	}

	n := &Nclient{
		Type: "BGP",
		Conn: conn,
	}

	return n
}
