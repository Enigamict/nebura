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
	Flag    uint8
}

type NclientXdp struct {
	ProType uint8
	Inter   string
}

type NclientIPv6RouteAdd struct {
	Nexthop Prefix
	NLRI    Prefix
	Flag    uint8
}

type NclientSeg6Add struct {
	EncapPrefix net.IP
	Segs        net.IP
}

type NclientSrEndAction struct {
	EndAction uint8
	EncapAddr net.IP
	NextHop   net.IP
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
	buf = append(buf, n.Flag)

	return buf, nil
}

func (n *NclientIPv6RouteAdd) writeTo() ([]byte, error) {

	var buf []byte
	buf = append(buf, n.NLRI.Prefix[:]...)
	buf = append(buf, n.NLRI.PrefixLen)
	buf = append(buf, n.Nexthop.Prefix[:]...)

	return buf, nil
}

func (n *NclientSeg6Add) writeTo() ([]byte, error) {

	var buf []byte
	buf = append(buf, n.EncapPrefix...)
	buf = append(buf, n.Segs...) // segsに合わせて可変長にする必要がある

	return buf, nil
}

func (n *NclientSrEndAction) writeTo() ([]byte, error) {
	var buf []byte

	buf = append(buf, n.EndAction)
	buf = append(buf, n.EncapAddr...)
	buf = append(buf, n.NextHop...)

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

func (n *NclientXdp) writeTo() ([]byte, error) {
	var buf []byte

	buf = append(buf, n.ProType)
	index, _ := net.InterfaceByName(n.Inter)
	buf = append(buf, byte(index.Index))
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

func (n *Nclient) SendNclientIPv4Route(prefix net.IP, nexthop net.IP, len uint8, flag uint8) error {

	body := &NclientRouteAdd{
		Nexthop: Prefix{
			Prefix:    nexthop,
			PrefixLen: 24,
		},
		NLRI: Prefix{
			Prefix:    prefix,
			PrefixLen: len,
		},
		Flag: flag,
	}

	NeburaHdrSize = 14

	n.sendNclientAPI(2, body)
	return nil

}

func (n *Nclient) SendNclientIPv6Route(prefix string, nexthop string, len uint8, index uint8) error {

	NexthopPrefix := net.ParseIP(nexthop).To16()
	AddPrefix := net.ParseIP(prefix).To16() // TODO: なぜか直接メンバ内でTo16()を実行すると、バイナリが入らないのでここで作ってから入れています

	body := &NclientIPv6RouteAdd{
		Nexthop: Prefix{
			Prefix: NexthopPrefix,
		},
		NLRI: Prefix{
			Prefix:    AddPrefix,
			PrefixLen: len,
		},
	}

	NeburaHdrSize = 36

	fmt.Printf("hex:%s", hex.Dump(body.Nexthop.Prefix))
	fmt.Printf("hex:%s", body.Nexthop.Prefix.String())

	n.sendNclientAPI(3, body)
	return nil

}

func (n *Nclient) SendNclientSeg6Add(encapaddr string, segs string) error {
	body := &NclientSeg6Add{
		EncapPrefix: net.ParseIP(encapaddr).To4(),
		Segs:        net.ParseIP(segs).To16(), // まだシングルでしか入れられない
	}

	NeburaHdrSize = 23
	fmt.Printf("%v", body)
	n.sendNclientAPI(4, body)
	return nil
}

func endActionType(en string) uint8 {

	switch en {
	case "END.DX4":
		return uint8(6) // TODO 増やす
	default:
		log.Printf("not endaction")
	}

	return 0
}

func (n *Nclient) SendNclientSRendAction(en string, nh string, ea string) error {

	body := &NclientSrEndAction{
		EndAction: endActionType(en),
		EncapAddr: net.ParseIP(ea).To16(),
		NextHop:   net.ParseIP(nh).To4(),
	}

	fmt.Printf("%v", body)
	NeburaHdrSize = 24
	n.sendNclientAPI(5, body)
	return nil
}

func (n *Nclient) SendNclientTcNetem(inter string, rate string) error {

	body := &NclientTcNetem{
		inter: inter,
		rate:  rate,
	}

	NeburaHdrSize = 9

	n.sendNclientAPI(6, body)
	return nil

}

func (n *Nclient) SendNclientXdp(pro uint8, inter string) error {

	body := &NclientXdp{
		ProType: pro,
		Inter:   inter,
	}

	NeburaHdrSize = 5

	n.sendNclientAPI(7, body)
	return nil

}

func NclientInit() *Nclient {
	conn, err := net.Dial("unix", "/tmp/test.sock")

	if err != nil {
		log.Fatal(err)
	}

	n := &Nclient{
		Conn: conn,
	}

	return n
}
