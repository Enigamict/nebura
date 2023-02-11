package nebura

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

const (
	bgpHederSize  = 19
	bgpMarkerSize = 16
)

type BgpMsg interface {
	writeTo() ([]byte, error)
}

type Peer struct {
	AS        uint16
	IdenTifer net.IP
	NeiAdrees net.IP
	Conn      net.Conn
}

type Message struct {
	Hdr []byte
	Msg BgpMsg
}

type Open struct {
	Version        uint8
	MyAS           uint16
	HoldTime       uint16
	BgpIdenTifer   net.IP
	OptParamLength uint8
	OptParm        []byte
}

type NLRIPrefix struct {
	Len  uint8
	NLRI net.IP
}

type Update struct {
	Nexthop net.IP
	NLRI    NLRIPrefix
}

func PeerInit(as uint16, iden net.IP, peer net.IP) *Peer {

	p := &Peer{
		AS:        as,
		IdenTifer: iden,
		NeiAdrees: peer,
	}
	return p
}

func (p *Peer) BgpStateEvent() error {
	return nil
}

func (m *Open) writeTo() ([]byte, error) {

	var buf []byte
	buf = make([]byte, OpenHdrlen)
	buf[0] = uint8(m.Version)
	binary.BigEndian.PutUint16(buf[1:3], m.MyAS)
	binary.BigEndian.PutUint16(buf[3:5], m.HoldTime)

	buf[5] = uint8(m.BgpIdenTifer[0])
	buf[6] = uint8(m.BgpIdenTifer[1])
	buf[7] = uint8(m.BgpIdenTifer[2])
	buf[8] = uint8(m.BgpIdenTifer[3])
	buf[9] = uint8(m.OptParamLength)
	return buf, nil
}

const Hdrlen = 19
const OpenHdrlen = 10
const OpenType = 1

func (p *Peer) SendMsg(hdr []byte, m BgpMsg) error {

	var buf []byte
	buf = make([]byte, 29)
	b, err := m.writeTo()

	if err != nil {
		return nil
	}

	buf = append(hdr, b...)
	_, err = p.Conn.Write(buf)

	if err != nil {
		log.Fatal(err)
		return nil
	}
	return nil
}

func (p *Peer) BgpSendOpenMsg() error {
	b, err := HdrInit(29, OpenType)

	if err != nil {
		log.Fatal(err)
		return nil
	}

	Open := &Open{
		Version:        uint8(4),
		MyAS:           uint16(p.AS),
		HoldTime:       uint16(180),
		BgpIdenTifer:   p.IdenTifer,
		OptParamLength: uint8(0),
	}

	p.SendMsg(b, Open)
	return nil
}

func (p *Peer) BgpSendkeepAliveMsg() error {
	b, err := HdrInit(Hdrlen, 4)

	if err != nil {
		log.Fatal(err)
		return nil
	}

	_, err = p.Conn.Write(b)
	return nil
}

func v4prefixPadding(data []byte) net.IP {
	return net.IP(data).To4()
}

func BgpupdateParse(data []byte) error {

	b := &Update{
		Nexthop: v4prefixPadding(data[18:22]),
		NLRI: NLRIPrefix{
			Len:  uint8(data[22]),
			NLRI: v4prefixPadding(data[23:27]),
		},
	}
	NclientSendMsg(b)
	return nil
}

func (p *Peer) PeerListen() error {

	var err error
	p.Conn, err = net.Dial("tcp", p.NeiAdrees.String()+":179")

	if err != nil {
		log.Fatal(err)
	}

	p.BgpSendOpenMsg()

	for {
		var header [19]byte
		if _, err := io.ReadFull(p.Conn, header[:]); err != nil {
			return nil
		}
		for i := 0; i < 16; i++ {
			if header[i] != 0xFF {
				return nil
			}
		}
		size := binary.BigEndian.Uint16(header[16:18])
		if size < 19 || size > 4096 {
			return nil
		}

		buf := make([]byte, size-19)
		if _, err := io.ReadFull(p.Conn, buf); err != nil {
			return nil
		}
		fmt.Printf("header:%v\n", header[18])
		switch header[18] {
		case 4:
			p.BgpSendkeepAliveMsg()
		case 2:
			BgpupdateParse(buf)
			fmt.Printf("NLRI:%v\n", buf[23:27])
			fmt.Printf("prefixLen:%v\n", buf[22])
			fmt.Printf("Nexthop:%v\n", buf[18:22])
		}
	}

}

func HdrInit(len uint16, bgpType uint8) ([]byte, error) {

	b := make([]byte, bgpHederSize)
	for i := 0; i < bgpMarkerSize; i++ {
		b[i] = 0xFF
	}

	binary.BigEndian.PutUint16(b[16:18], len)
	b[18] = bgpType
	return b, nil
}
