package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"syscall"

	"encoding/binary"
)

type APIType uint16
type RouteType uint8
type TestType uint8
type afi uint8

type Software struct {
	name    string
	version float64
}

const (
	testSystem TestType = iota //0
	testSystem1
)

const (
	afiIP    afi = 1
	afiIP6   afi = 2
	afiEther afi = 3
	afiMax   afi = 4
)

const (
	routeSystem RouteType = iota //0
	routeKernel
	routeConnect
	RouteStatic
	routeRIP
	routeRIPNG
	routeOSPF
	routeOSPF6
	routeISIS
	RouteBGP
	routePIM   // 10
	routeEIGRP // FRRRouting version 4 (Zapi5) adds.
	routeNHRP
	routeHSLS
	routeOLSR
	routeTABLE
	routeLDP
	routeVNC
	routeVNCDirect
	routeVNCDirectRH
	routeBGPDirect
	routeBGPDirectEXT
	routeBABEL
	routeSHARP
	routePBR        // FRRRouting version 5 (Zapi5) adds.
	routeBFD        // FRRRouting version 6 (Zapi6) adds.
	routeOpenfabric // FRRRouting version 7 (Zapi6) adds.
	routeVRRP       // FRRRouting version 7.2 (Zapi6) adds.
	routeNHG        // FRRRouting version 7.3 (Zapi6) adds.
	routeSRTE       // FRRRouting version 7.5 (Zapi6) adds.
	routeAll
	routeMax // max value for error
)

type Header struct {
	Len     uint16
	Marker  uint8
	Version uint8
	VrfID   uint32 // ZAPI v4: 16bits, v5: 32bits
	Command APIType
}

type Body interface {
	decodeFromBytes([]byte, uint8, Software) error
	serialize(uint8, Software) ([]byte, error)
	string(uint8, Software) string
}

type Message struct {
	Header Header
	Body   Body
}

type Client struct {
	outgoing      chan *Message
	incoming      chan *Message
	redistDefault RouteType
	conn          net.Conn
	Version       uint8
	Software      Software
}

type routerIDUpdateBody struct {
	length uint8
	prefix net.IP
	afi    afi
}

type helloBody struct {
	redistDefault RouteType
	instance      uint16
	sessionID     uint32 // frr7.4, 7.5, 8, 8.1, 8.2
	receiveNotify uint8
	synchronous   uint8 // frr7.4, 7.5, 8, 8.1, 8.2
}

const (
	headerMarker    uint8 = 255
	frrHeaderMarker uint8 = 254
)

const (
	interfaceAdd           APIType = iota // 0 // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceDelete                       // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceAddressAdd                   // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceAddressDelete                // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceUp                           // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceDown                         // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	_interfaceSetMaster
	_interfaceSetProtoDown // Add in frr 7.2
	RouteAdd               // RouteAdd is referred in zclient_test
	RouteDelete            // RouteDelete is referred in zclient_test
	_routeNotifyOwner      // 10
	redistributeAdd
	_redistributeDelete
	_redistributeDefaultAdd
	_redistributeDefaultDelete
	routerIDAdd
	_routerIDDelete
	routerIDUpdate
	hello
)

func closeChannel(ch chan *Message) bool {
	select {
	case _, ok := <-ch:
		if ok {
			close(ch)
			return true
		}
	default:
	}
	return false
}

func addressByteLength(family uint8) (int, error) {
	switch family {
	case syscall.AF_INET:
		return net.IPv4len, nil
	case syscall.AF_INET6:
		return net.IPv6len, nil
	}
	return 0, fmt.Errorf("unknown address family: %d", family)
}

func (b *routerIDUpdateBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	family := data[0]

	addrlen, err := addressByteLength(family)
	if err != nil {
		return err
	}
	b.prefix = data[1 : 1+addrlen] //zclient_stream_get_prefix
	b.length = data[1+addrlen]     //zclient_stream_get_prefix
	return nil
}
func (h *Header) decodeFromBytes(data []byte) error {
	if uint16(len(data)) < 4 {
		return fmt.Errorf("not all ZAPI message header")
	}
	h.Len = binary.BigEndian.Uint16(data[0:2])
	h.Marker = data[2]
	h.Version = data[3]
	if uint16(len(data)) < HeaderSize(h.Version) {
		return fmt.Errorf("not all ZAPI message header")
	}
	switch h.Version {
	case 2:
		h.Command = APIType(binary.BigEndian.Uint16(data[4:6]))
	case 3, 4:
		h.VrfID = uint32(binary.BigEndian.Uint16(data[4:6]))
		h.Command = APIType(binary.BigEndian.Uint16(data[6:8]))
	case 5, 6:
		h.VrfID = binary.BigEndian.Uint32(data[4:8])
		h.Command = APIType(binary.BigEndian.Uint16(data[8:10]))
	default:
		return fmt.Errorf("unsupported ZAPI version: %d", h.Version)
	}
	return nil
}

func (b *routerIDUpdateBody) serialize(version uint8, software Software) ([]byte, error) {
	if version == 6 && software.name == "frr" && software.version >= 7.5 {
		return []byte{0x00, uint8(b.afi)}, nil //stream_putw(s, afi);

	}
	return []byte{}, nil
}

func (b *routerIDUpdateBody) string(version uint8, software Software) string {
	return fmt.Sprintf("id: %s/%d", b.prefix.String(), b.length)
}

func (h *Header) serialize() ([]byte, error) {
	buf := make([]byte, HeaderSize(h.Version))
	binary.BigEndian.PutUint16(buf[0:2], h.Len)
	buf[2] = h.Marker
	buf[3] = h.Version
	switch h.Version {
	case 2:
		binary.BigEndian.PutUint16(buf[4:6], uint16(h.Command))
	case 3, 4:
		binary.BigEndian.PutUint16(buf[4:6], uint16(h.VrfID))
		binary.BigEndian.PutUint16(buf[6:8], uint16(h.Command))
	case 5, 6:
		binary.BigEndian.PutUint32(buf[4:8], uint32(h.VrfID))
		binary.BigEndian.PutUint16(buf[8:10], uint16(h.Command))
	default:
		return nil, fmt.Errorf("unsupported ZAPI version: %d", h.Version)
	}
	return buf, nil
}

func (b *helloBody) serialize(version uint8, software Software) ([]byte, error) {
	if version < 4 {
		return []byte{uint8(b.redistDefault)}, nil
	}
	var buf []byte
	if version == 6 && software.name == "frr" && software.version >= 7.4 {
		buf = make([]byte, 9)
	} else if version > 4 {
		buf = make([]byte, 4)
	} else if version == 4 {
		buf = make([]byte, 3)
	}
	buf[0] = uint8(b.redistDefault)
	binary.BigEndian.PutUint16(buf[1:3], b.instance)
	if version == 6 && software.name == "frr" && software.version >= 7.4 {
		binary.BigEndian.PutUint32(buf[3:7], b.sessionID)
		buf[7] = b.receiveNotify
		buf[8] = b.synchronous
	} else if version > 4 {
		buf[3] = b.receiveNotify
	}
	return buf, nil
}

func (m *Message) serialize(software Software) ([]byte, error) {
	var body []byte
	if m.Body != nil {
		var err error
		body, err = m.Body.serialize(m.Header.Version, software)
		if err != nil {
			return nil, err
		}
	}
	m.Header.Len = uint16(len(body)) + HeaderSize(m.Header.Version)
	hdr, err := m.Header.serialize()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func HeaderSize(version uint8) uint16 {
	switch version {
	case 3, 4:
		return 8
	case 5, 6:
		return 10
	}
	return 6 // version == 2
}

func HeaderMarker(version uint8) uint8 {
	if version > 3 {
		return frrHeaderMarker
	}
	return headerMarker
}

func (b *helloBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	b.redistDefault = RouteType(data[0])
	if version > 3 { //frr
		b.instance = binary.BigEndian.Uint16(data[1:3])
		if version == 6 && software.name == "frr" && software.version >= 7.4 {
			b.sessionID = binary.BigEndian.Uint32(data[3:7])
			b.receiveNotify = data[7]
			b.synchronous = data[8]
		} else if version > 4 {
			b.receiveNotify = data[3]
		}
	}
	return nil
}

func (b *helloBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"route_type")
}

func (c *Client) send(m *Message) {
	c.outgoing <- m
}

func (c *Client) sendCommand(command APIType, vrfID uint32, body Body) error {
	m := &Message{
		Header: Header{
			Len:     HeaderSize(c.Version),
			Marker:  HeaderMarker(c.Version),
			Version: c.Version,
			VrfID:   vrfID,
			Command: hello,
		},
		Body: body,
	}
	c.send(m)
	return nil
}

func (c *Client) SendRouterIDAdd() error {
	bodies := make([]*routerIDUpdateBody, 0)
	for _, afi := range []afi{afiIP, afiIP6} {
		bodies = append(bodies, &routerIDUpdateBody{
			afi: afi,
		})
	}
	for _, body := range bodies {
		c.sendCommand(routerIDAdd, 0, body)
	}
	return nil
}

func (c *Client) SendHello() error {
	if c.redistDefault > 0 {
		body := &helloBody{
			redistDefault: c.redistDefault,
			instance:      0,
		}
		return c.sendCommand(hello, 0, body)
	}
	return nil
}

func main1() {
	m := &Message{
		Header: Header{
			Len:    HeaderSize(5),
			Marker: HeaderMarker(5),
		},
	}
	s := Software{
		name:    "frr",
		version: 8.1,
	}
	b, err := m.serialize(s)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x", b)
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func main() {
	conn, err := net.Dial("unix", "/var/run/frr/zserv.api")

	if err != nil {
		log.Fatal(err)
	}

	outgoing := make(chan *Message)
	incoming := make(chan *Message, 64)

	s := Software{
		name:    "frr",
		version: 8.1,
	}

	c := &Client{
		outgoing:      outgoing,
		incoming:      incoming,
		redistDefault: RouteBGP,
		conn:          conn,
		Version:       6,
		Software:      s,
	}

	go func() {
		for {
			m, more := <-outgoing // c.sendhello() 後
			if more {
				b, err := m.serialize(s)
				if err != nil {
					continue
				}

				_, err = conn.Write(b)
			}
		}
	}()

	c.SendHello()
	c.SendRouterIDAdd()

	for {
		headerBuf, err := readAll(conn, int(HeaderSize(6)))
		if err != nil {
			log.Fatal(err)
		}
		log.Print("%v", headerBuf)
		//
		hd := &Header{}
		err = hd.decodeFromBytes(headerBuf)
		if err != nil {
			log.Fatal(err)
		}
		bodyBuf, err := readAll(conn, int(hd.Len-HeaderSize(6)))
		if err != nil {
			log.Fatal(err)
		}
		log.Print("%v", bodyBuf)
		//
		//

	}
	//
	fmt.Printf("testes")
}
