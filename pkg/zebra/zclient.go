// The overall Zclient communication section and implementation is based on the Zebra communication
// section of GoBGP.
// If there are any problems, etc., please let me know.

package zebra

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"syscall"
)

type APIType uint16
type RouteType uint8
type TestType uint8
type nexthopType uint8
type Flag uint64
type MessageFlag uint32
type Safi uint8

const ZebraHeaderSize = 10 // FRR 8.1

const (
	safiUnspec Safi = iota
	SafiUnicast
)

const (
	headerMarker    uint8 = 255
	frrHeaderMarker uint8 = 254
)

const (
	_                      nexthopType = iota
	nexthopTypeIFIndex                 // 1
	nexthopTypeIPv4                    // 2
	nexthopTypeIPv4IFIndex             // 3
	nexthopTypeIPv6                    // 4
	nexthopTypeIPv6IFIndex             // 5
	nexthopTypeBlackhole               // 6
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

const ( // For FRRouting version 4, 5 and 6 (ZAPI version 5 and 6).  // MessageNexthop is referred in zclient
	MessageNexthop MessageFlag = 0x01
	// MessageDistance is referred in zclient_test
	MessageDistance MessageFlag = 0x02
	// MessageMetric is referred in zclient
	MessageMetric MessageFlag = 0x04
	messageTag    MessageFlag = 0x08
	// MessageMTU is referred in zclient_test
	MessageMTU    MessageFlag = 0x10
	messageSRCPFX MessageFlag = 0x20
	// MessageLabel is referred in zclient
	MessageLabel          MessageFlag = 0x40  // deleted in frr7.3
	messageBackupNexthops MessageFlag = 0x40  // added in frr7.4
	messageNhg            MessageFlag = 0x80  // added in frr8
	messageTableID        MessageFlag = 0x100 // frr8: 0x100, frr5&6&7.x: 0x80
	messageSRTE           MessageFlag = 0x200 // frr8: 0x200, frr7.5: 0x100
	messageOpaque         MessageFlag = 0x400 // introduced in frr8
)

type Software struct {
	name    string
	version float64
}

type Header struct {
	Len     uint16
	Marker  uint8
	Version uint8
	VrfID   uint32 // ZAPI v4: 16bits, v5: 32bits
	Command APIType
}

type Body interface {
	writeTo() ([]byte, error)
}

type Message struct {
	Header Header
	Body   Body
}

type Prefix struct {
	Family    uint8
	PrefixLen uint8
	Prefix    net.IP
}

type Nexthop struct {
	Type    nexthopType
	VrfID   uint32
	Ifindex uint32
	flags   uint8
	Gate    net.IP
}

type BGPRouteBody struct {
	Type     RouteType
	instance uint16
	Flags    Flag
	Message  MessageFlag
	Safi     Safi
	Prefix   Prefix
	Nexthops []Nexthop
	Distance uint8
	Metric   uint32
	Mtu      uint32
	API      APIType
}

type BgpClient struct {
	routeType RouteType
	Conn      net.Conn
	Version   uint8
}

type helloBody struct {
	routeType     RouteType
	instance      uint16
	sessionID     uint32 // frr7.4, 7.5, 8, 8.1, 8.2
	receiveNotify uint8
	synchronous   uint8 // frr7.4, 7.5, 8, 8.1, 8.2
}

func (h *Header) writeTo() ([]byte, error) {
	buf := make([]byte, ZebraHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], h.Len)
	buf[2] = h.Marker
	buf[3] = h.Version
	binary.BigEndian.PutUint32(buf[4:8], uint32(h.VrfID))
	binary.BigEndian.PutUint16(buf[8:10], uint16(h.Command))
	return buf, nil
}

func (m *Message) writeTo() ([]byte, error) {
	var body []byte
	if m.Body != nil {
		var err error
		body, err = m.Body.writeTo()
		if err != nil {
			return nil, err
		}
	}
	m.Header.Len = uint16(len(body)) + ZebraHeaderSize
	hdr, err := m.Header.writeTo()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func (b *helloBody) writeTo() ([]byte, error) {
	var buf []byte
	buf = make([]byte, 9)
	buf[0] = uint8(b.routeType)
	binary.BigEndian.PutUint16(buf[1:3], b.instance)
	binary.BigEndian.PutUint32(buf[3:7], b.sessionID)
	buf[7] = b.receiveNotify
	buf[8] = b.synchronous
	return buf, nil
}

func (c *BgpClient) sendCommand(command APIType, vrfID uint32, body Body) error {
	m := &Message{
		Header: Header{
			Len:     ZebraHeaderSize, // Zebra ver 6 = 10
			Marker:  frrHeaderMarker,
			Version: c.Version,
			VrfID:   vrfID,
			Command: command,
		},
		Body: body,
	}

	buf, _ := m.writeTo()
	c.Conn.Write(buf)
	return nil
}

func ZebraByteRead(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

type nexthopProcessFlag uint8

const (
	nexthopHasType                nexthopProcessFlag = 0x01
	nexthopHasVrfID               nexthopProcessFlag = 0x02
	nexthopHasFlag                nexthopProcessFlag = 0x04
	nexthopHasOnlink              nexthopProcessFlag = 0x08
	nexthopProcessIPToIPIFindex   nexthopProcessFlag = 0x10
	nexthopProcessIFnameToIFindex nexthopProcessFlag = 0x20 // for quagga
)

func nexthopProcessFlagForBGPRouteBody() nexthopProcessFlag {
	processFlag := (nexthopHasVrfID | nexthopHasType)
	processFlag |= (nexthopHasFlag | nexthopProcessIPToIPIFindex)
	return processFlag
}

func familyFromPrefix(prefix net.IP) uint8 {
	if prefix.To4() != nil {
		return syscall.AF_INET
	} else if prefix.To16() != nil {
		return syscall.AF_INET6
	}
	return syscall.AF_UNSPEC
}

func (n Nexthop) gateToType() nexthopType {
	return nexthopTypeIPv4
}

func (t nexthopType) ipToIPIFIndex() nexthopType {
	if t == nexthopTypeIPv4 {
		return nexthopTypeIPv4IFIndex
	} else if t == nexthopTypeIPv6 {
		return nexthopTypeIPv6IFIndex
	}
	return t
}

func (n Nexthop) encode(processFlag nexthopProcessFlag, message MessageFlag, apiFlag Flag) []byte {
	var buf []byte
	if processFlag&nexthopHasVrfID > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, n.VrfID)
		buf = append(buf, tmpbuf...)
	}
	if processFlag&nexthopHasType > 0 {
		if n.Type == nexthopType(0) {
			n.Type = n.gateToType()
		}
		buf = append(buf, uint8(n.Type))
	}
	if processFlag&nexthopHasFlag > 0 || processFlag&nexthopHasOnlink > 0 {
		buf = append(buf, n.flags)
	}

	nhType := n.Type
	if processFlag&nexthopProcessIPToIPIFindex > 0 {
		nhType = nhType.ipToIPIFIndex()
	}

	if nhType == nexthopTypeIPv4 ||
		nhType == nexthopTypeIPv4IFIndex {
		buf = append(buf, n.Gate.To4()...)
	}

	return buf
}

func (b *BGPRouteBody) writeTo() ([]byte, error) {
	var buf []byte
	numNexthop := len(b.Nexthops)

	bufInitSize := 12
	buf = make([]byte, bufInitSize)

	buf[0] = uint8(RouteBGP)
	binary.BigEndian.PutUint16(buf[1:3], uint16(b.instance))
	binary.BigEndian.PutUint32(buf[3:7], uint32(b.Flags))
	binary.BigEndian.PutUint32(buf[7:11], uint32(5))
	buf[11] = uint8(b.Safi)
	b.Prefix.Family = familyFromPrefix(b.Prefix.Prefix)
	buf = append(buf, b.Prefix.Family)

	byteLen := (int(b.Prefix.PrefixLen) + 7) / 8
	buf = append(buf, b.Prefix.PrefixLen)
	buf = append(buf, b.Prefix.Prefix[:byteLen]...)

	processFlag := nexthopProcessFlagForBGPRouteBody()
	tmpbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tmpbuf, uint16(numNexthop))
	buf = append(buf, tmpbuf...)
	for _, nexthop := range b.Nexthops {
		buf = append(buf, nexthop.encode(processFlag, b.Message, b.Flags)...)
	}

	metricbuf := make([]byte, 8)
	binary.BigEndian.PutUint32(metricbuf, b.Metric)
	binary.BigEndian.PutUint32(metricbuf, b.Mtu)
	buf = append(buf, metricbuf...)
	return buf, nil
}

func (c *BgpClient) SendHello() error {
	if c.routeType > 0 {
		body := &helloBody{
			routeType: c.routeType,
			instance:  0,
		}
		return c.sendCommand(hello, 0, body)
	}
	return nil
}

func (c *BgpClient) SendRouteAdd(prefix string, nexthop string) error {

	body := &BGPRouteBody{
		Type:     RouteBGP,
		Flags:    0,
		Message:  MessageNexthop,
		Safi:     SafiUnicast,
		instance: 0,
		Prefix: Prefix{
			Prefix:    net.ParseIP(prefix).To4(),
			PrefixLen: uint8(32),
		},
		Nexthops: []Nexthop{
			{
				Gate: net.ParseIP(nexthop),
			},
		},
		Distance: uint8(0),
		Metric:   uint32(0),
		Mtu:      uint32(0),
	}
	return c.sendCommand(RouteAdd, 0, body) // body interface
}

func ZebraClientInit() (*BgpClient, error) {
	conn, err := net.Dial("unix", "/var/run/frr/zserv.api")

	if err != nil {
		log.Fatal(err)
	}

	c := &BgpClient{
		routeType: RouteBGP,
		Conn:      conn,
		Version:   6,
	}

	return c, nil

}
