package nebura

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/Enigamict/zebraland/pkg/zebra"
)

type BgpType uint8

const (
	BgpOpenType      = 1
	BgpUpdateType    = 2
	BgpKeepAliveType = 4
)

const (
	bgpHederSize  = 19
	bgpMarkerSize = 16
)

type (
	Event interface {
		Loop(*Peer) error
	}

	ConectActiveEvent struct{}

	OpenSentEvent    struct{}
	OpenConfirmEvent struct {
		data []byte
	}
	EstabEvent struct {
		data []byte
	}

	UpdateEvent struct {
		data []byte
	}
)

type BgpMsg interface {
	writeTo() ([]byte, error)
}

type Peer struct {
	AS        uint16
	IdenTifer net.IP
	NeiAdrees net.IP
	Select    string
	State     string
	eventChan chan Event
	Conn      net.Conn
}

type Hdr struct {
	Marker []byte
	Len    uint16
	Type   uint8
}

type Message struct {
	Hdr Hdr
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

type KeepAlive struct {
}

type NLRIPrefix struct {
	Len  uint8
	NLRI net.IP
}

type Update struct {
	Nexthop net.IP
	NLRI    NLRIPrefix
}

func (t ConectActiveEvent) Loop(p *Peer) error {
	p.SetState("Conect")
	log.Printf("BGP State: %s", p.State)

	var err error
	p.Conn, err = net.Dial("tcp", p.NeiAdrees.String()+":179")

	log.Printf("BGP Peer Listen...\n")
	log.Printf("Listen addr %s...\n", p.NeiAdrees.String())
	p.SetState("Active")
	log.Printf("BGP State: %s", p.State)

	if err != nil {
		log.Fatal(err)
	}

	p.eventChan <- OpenSentEvent{}
	return nil
}

func (t OpenSentEvent) Loop(p *Peer) error {
	p.SetState("OpenSent")
	log.Printf("BGP State: %s", p.State)

	p.BgpSendOpenMsg()

	go p.BgpRecvMsg()

	return nil
}

func (t UpdateEvent) Loop(p *Peer) error {

	BgpupdateParse(t.data, p.Select)
	return nil
}

func (t OpenConfirmEvent) Loop(p *Peer) error {
	p.BgpSendkeepAliveMsg()
	return nil
}

func (t EstabEvent) Loop(p *Peer) error {
	p.SetState("Estab")
	log.Printf("BGP State: %s", p.State)

	p.BgpSendkeepAliveMsg()

	return nil
}

func (p *Peer) Run() error {

	log.Printf("BGP State: %s", p.State)
	p.eventChan <- ConectActiveEvent{}

	for {
		select {
		case e := <-p.eventChan:
			if err := e.Loop(p); err != nil {
				return err
			}
		}
	}
}

func PeerInit(as uint16, iden net.IP, peer net.IP, routing string) *Peer {

	p := &Peer{
		AS:        as,
		IdenTifer: iden,
		Select:    routing,
		State:     "Idle",
		eventChan: make(chan Event, 10),
		NeiAdrees: peer,
	}
	return p
}

func (h *Hdr) writeTo() ([]byte, error) {

	buf := make([]byte, 19)
	for i := 0; i < bgpMarkerSize; i++ {
		buf[i] = 0xFF
	}
	binary.BigEndian.PutUint16(buf[16:18], h.Len)
	buf[18] = uint8(h.Type)
	return buf, nil
}

func (m *Message) writeTo() ([]byte, error) {

	var buf []byte
	var msgbuf []byte
	var headerbuf []byte

	headerbuf, _ = m.Hdr.writeTo()
	msgbuf, _ = m.Msg.writeTo()

	buf = append(buf, headerbuf...)
	buf = append(buf, msgbuf...)
	return buf, nil
}

func (m *Open) writeTo() ([]byte, error) {

	var buf []byte
	buf = make([]byte, 5)
	buf[0] = uint8(m.Version)
	binary.BigEndian.PutUint16(buf[1:3], m.MyAS)
	binary.BigEndian.PutUint16(buf[3:5], m.HoldTime)

	buf = append(buf, m.BgpIdenTifer...)
	buf = append(buf, m.OptParamLength)
	return buf, nil
}

func (k *KeepAlive) writeTo() ([]byte, error) {
	return nil, nil
}

const Hdrlen = 19
const OpenHdrlen = 10

func (p *Peer) SendMsg(len uint16, bgpType uint8, m BgpMsg) error {

	s := &Message{
		Hdr: Hdr{
			Len:  len,
			Type: bgpType,
		},
		Msg: m,
	}

	buf, _ := s.writeTo()
	p.Conn.Write(buf)
	return nil
}

func (p *Peer) BgpSendOpenMsg() error {

	Open := &Open{
		Version:        uint8(4),
		MyAS:           uint16(p.AS),
		HoldTime:       uint16(180),
		BgpIdenTifer:   p.IdenTifer,
		OptParamLength: uint8(0),
	}

	p.SendMsg(bgpHederSize+10, uint8(BgpOpenType), Open)
	return nil
}

func (p *Peer) BgpSendkeepAliveMsg() error {

	p.SendMsg(bgpHederSize, uint8(BgpKeepAliveType), &KeepAlive{})
	return nil
}

func BgpupdateParse(data []byte, routing string) error {

	b := &Update{
		Nexthop: prefixPadding(data[18:22]),
		NLRI: NLRIPrefix{
			Len:  uint8(data[22]),
			NLRI: prefixPadding(data[23:27]),
		},
	}

	switch routing {
	case "nebura":
		var n = NclientInit("BGP")
		log.Printf("Nebura Conect...\n")
		n.SendNclientIPv4RouteAdd(b.NLRI.NLRI, b.Nexthop, b.NLRI.Len)
	case "zebra":

		c, err := zebra.ZebraClientInit()

		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Zebra Conect...\n")

		c.SendHello()
		c.SendRouteAdd(b.NLRI.NLRI.String(), b.Nexthop.String())

	default:
		fmt.Printf("Routing Software no Select\n")
	}
	return nil
}

const BgpMsgMax = 4096

func BgpHdrRead(conn net.Conn) ([]byte, uint8, error) {
	var header [bgpHederSize]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, 0, nil
	}

	for i := 0; i < 16; i++ {
		if header[i] != 0xFF {
			return nil, 0, nil
		}
	}

	size := binary.BigEndian.Uint16(header[16:18])
	if size < bgpHederSize || size > BgpMsgMax {
		return nil, 0, nil
	}

	buf := make([]byte, size-bgpHederSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, 0, nil
	}

	TypeCode := uint8(header[18])

	for {
		switch TypeCode {
		case BgpOpenType:
			log.Printf("BGP Open Recv...\n")
			return buf, TypeCode, nil
		case BgpKeepAliveType:
			log.Printf("BGP KeepAlive Recv...\n")
			return buf, TypeCode, nil
		case BgpUpdateType:
			log.Printf("BGP Update Recv...\n")
			return buf, TypeCode, nil
		default:
			log.Printf("BGP Unknown...\n")
			return buf, TypeCode, nil

		}
	}

}

func (p *Peer) SetState(s string) {
	defer r.mu.Unlock()
	r.mu.Lock()
	p.State = s
}

func (p *Peer) ParseBgpOpen(data []byte) error {

	p.BgpSendOpenMsg()
	return nil
}

func (p *Peer) ParseBgpKeepAlive(data []byte) error {

	p.SetState("Estab")
	log.Printf("State Estab...\n")

	p.BgpSendkeepAliveMsg()
	return nil
}

func (p *Peer) BgpRecvMsg() {

	for {

		buf, TypeCode, err := BgpHdrRead(p.Conn)

		if err != nil {
			log.Fatal(err)
		}

		switch TypeCode {
		case BgpOpenType:
			p.eventChan <- OpenConfirmEvent{buf}
		case BgpKeepAliveType:
			p.eventChan <- EstabEvent{buf}
		case BgpUpdateType:
			p.eventChan <- UpdateEvent{buf}
		default:
			break
		}
	}

}
