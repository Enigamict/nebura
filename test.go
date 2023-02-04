package main

/*
#cgo LDFLAGS: -L. -lipv4add
#include "libnetlink.h"
#include "ipv4add.h"
*/
import "C"

import (
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"zebraland/unix_server"

	"encoding/binary"
)

type APIType uint16
type RouteType uint8
type TestType uint8
type afi uint8
type nexthopType uint8
type Flag uint64
type MessageFlag uint32
type Safi uint8

type ApiType uint8

const (
	testHello ApiType = iota //0
	routeAdd
	netlinkMode
)

type Software struct {
	name    string
	version float64
}

const (
	afiIP    afi = 1
	afiIP6   afi = 2
	afiEther afi = 3
	afiMax   afi = 4
)

const ( // For FRRouting version 7 (zebra API version 6), these are defined in lib/zclient.h
	// FlagAllowRecursion is referred in zclient, and it is renamed from ZEBRA_FLAG_INTERNAL (https://github.com/FRRouting/frr/commit/4e8b02f4df5d6bcfde6390955b8feda2a17dc9bd)
	FlagAllowRecursion Flag = 0x01 // quagga, frr3, frr4, frr5, frr6, frr7
	flagSelfRoute      Flag = 0x02 // quagga, frr3, frr4, frr5, frr6, frr7
	// FlagIBGP is referred in zclient
	FlagIBGP Flag = 0x04
	// FlagSelected referred in zclient_test
	FlagSelected      Flag = 0x08
	flagFIBOverride   Flag = 0x10
	flagEvpnRoute     Flag = 0x20
	flagRRUseDistance Flag = 0x40
	flagOnlink        Flag = 0x80  // frr7.0 only, this vale is deleted in frr7.1
	flagTrapped       Flag = 0x80  // added in frr8
	flagOffloaded     Flag = 0x100 // added in frr8
	flagOffloadFailed Flag = 0x200 // added in frr8
)

const (
	safiUnspec Safi = iota // added in FRRouting version 7.2 (Zapi 6)
	SafiUnicast
	safiMulticast
	safiMplsVpn
	safiEncap
	safiEvpn
	safiLabeledUnicast
	safiFlowspec // added in FRRouting version 5 (Zapi 5)
	safiMax
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

type ApiHeader struct {
	Len     uint16
	Command uint8
}

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

type Prefix struct {
	Family    uint8
	PrefixLen uint8
	Prefix    net.IP
}

type Nexthop struct {
	Type            nexthopType //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	VrfID           uint32      //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	Ifindex         uint32      // Ifindex is referred in zclient_test
	flags           uint8       //FRR7.1, FRR7.2 FRR7.3, FRR7.4, FRR7.5, FRR8, FRR8.1
	Gate            net.IP      //union { union g_addr gate;
	blackholeType   uint8       //        enum blackhole_type bh_type;}
	LabelNum        uint8       //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	MplsLabels      []uint32    //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	rmac            [6]byte     //FRR6, FRR7.x, FRR8, FRR8.1
	weight          uint32      //FRR7.3, FRR7.4, FRR7.5, FRR8, FRR8.1
	backupNum       uint8       //FRR7.4, FRR7.5, FRR8, FRR8.1
	backupIndex     []uint8     //FRR7.5, FRR8, FRR8.1
	srteColor       uint32      //FRR7.5, FRR8, FRR8.1
	seg6localAction uint32      //FRR8.1
	seg6Segs        net.IP      //strcut in6_addr // FRR8.1
}

type IPRouteBody struct {
	Type           RouteType   // FRR4&FRR5&FRR6&FRR7.x&FRR8
	instance       uint16      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Flags          Flag        // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Message        MessageFlag // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Safi           Safi        // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Prefix         Prefix      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	srcPrefix      Prefix      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Nexthops       []Nexthop   // FRR4&FRR5&FRR6&FRR7.x&FRR8
	backupNexthops []Nexthop   // added in frr7.4, FRR7.4&FRR7.5&FRR8
	nhgid          uint32      // added in frr8
	Distance       uint8       // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Metric         uint32      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	tag            uint32      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Mtu            uint32      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	tableID        uint32      // FRR5&FRR6&FRR7.x&FRR8 (nh_vrf_id in FRR4)
	srteColor      uint32      // added in frr7.5, FRR7.5&FRR8
	API            APIType     // API is referred in zclient_test
	//vrfID        uint32    // lib/zebra.h:typedef uint32_t vrf_id_t;
}

type Client struct {
	outgoing      chan *Message
	redistDefault RouteType
	conn          net.Conn
	Version       uint8
	Software      Software
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
			Command: command,
		},
		Body: body,
	}
	c.send(m)
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

func readAll(conn net.Conn, length int) ([]byte, error) {
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

func nexthopProcessFlagForIPRouteBody(version uint8, software Software, isDecode bool) nexthopProcessFlag {
	if version < 5 {
		if isDecode {
			return nexthopProcessFlag(0) // frr3&quagga don't have type&vrfid
		}
		return nexthopHasType // frr3&quagga need type for encode(serialize)
	}
	processFlag := (nexthopHasVrfID | nexthopHasType) // frr4, 5, 6, 7
	if version == 6 && software.name == "frr" {
		if software.version >= 7.3 {
			processFlag |= (nexthopHasFlag | nexthopProcessIPToIPIFindex)
		} else if software.version >= 7.1 {
			processFlag |= nexthopHasOnlink
		}
	}
	// nexthopHasType nexthopProcessIPToIPIFindex
	return processFlag
}

const (
	zapi4RouteNHRP RouteType = iota + routePIM + 1
	zapi4RouteHSLS
	zapi4RouteOLSR
	zapi4RouteTABLE
	zapi4RouteLDP
	zapi4RouteVNC
	zapi4RouteVNCDirect
	zapi4RouteVNCDirectRH
	zapi4RouteBGPDixrect
	zapi4RouteBGPDirectEXT
	zapi4RouteAll
)

var routeTypeZapi4Map = map[RouteType]RouteType{
	routeNHRP:         zapi4RouteNHRP,
	routeHSLS:         zapi4RouteHSLS,
	routeOLSR:         zapi4RouteOLSR,
	routeTABLE:        zapi4RouteTABLE,
	routeLDP:          zapi4RouteLDP,
	routeVNC:          zapi4RouteVNC,
	routeVNCDirect:    zapi4RouteVNCDirect,
	routeVNCDirectRH:  zapi4RouteVNCDirectRH,
	routeBGPDirect:    zapi4RouteBGPDixrect,
	routeBGPDirectEXT: zapi4RouteBGPDirectEXT,
	routeAll:          zapi4RouteAll,
}

const (
	zapi3RouteHSLS RouteType = iota + routePIM + 1
	zapi3RouteOLSR
	zapi3RouteBABEL
	zapi3RouteNHRP // quagga 1.2.4
)

var routeTypeZapi3Map = map[RouteType]RouteType{
	routeHSLS:  zapi3RouteHSLS,
	routeOLSR:  zapi3RouteOLSR,
	routeBABEL: zapi3RouteBABEL,
	routeNHRP:  zapi3RouteNHRP,
}

func (t RouteType) toEach(version uint8) RouteType {
	if t <= routePIM || version > 4 { // not need to convert
		return t
	}
	routeTypeMap := routeTypeZapi4Map
	if version < 4 {
		routeTypeMap = routeTypeZapi3Map
	}
	backward, ok := routeTypeMap[t]
	if ok {
		return backward // success to convert
	}
	return routeMax // fail to convert and error value
}

func familyFromPrefix(prefix net.IP) uint8 {
	if prefix.To4() != nil {
		return syscall.AF_INET
	} else if prefix.To16() != nil {
		return syscall.AF_INET6
	}
	return syscall.AF_UNSPEC
}

func (n Nexthop) gateToType(version uint8) nexthopType {
	if n.Gate.To4() != nil {
		if version > 4 && n.Ifindex > 0 {
			return nexthopTypeIPv4IFIndex
		}
		return nexthopTypeIPv4.toEach(version)
	} else if n.Gate.To16() != nil {
		if version > 4 && n.Ifindex > 0 {
			return nexthopTypeIPv6IFIndex
		}
		return nexthopTypeIPv6.toEach(version)
	} else if n.Ifindex > 0 {
		return nexthopTypeIFIndex.toEach(version)
	} else if version > 4 {
		return nexthopTypeBlackhole
	}
	return nexthopType(0)
}

func (t nexthopType) ipToIPIFIndex() nexthopType {
	// process of nexthopTypeIPv[4|6] is same as nexthopTypeIPv[4|6]IFIndex
	// in IPRouteBody of frr7.3 and NexthoUpdate of frr
	if t == nexthopTypeIPv4 {
		return nexthopTypeIPv4IFIndex
	} else if t == nexthopTypeIPv6 {
		return nexthopTypeIPv6IFIndex
	}
	return t
}

// For Quagga.
const (
	nexthopTypeIFName              nexthopType = iota + 2 // 2
	backwardNexthopTypeIPv4                               // 3
	backwardNexthopTypeIPv4IFIndex                        // 4
	nexthopTypeIPv4IFName                                 // 5
	backwardNexthopTypeIPv6                               // 6
	backwardNexthopTypeIPv6IFIndex                        // 7
	nexthopTypeIPv6IFName                                 // 8
	backwardNexthopTypeBlackhole                          // 9
)

var nexthopTypeMap = map[nexthopType]nexthopType{
	nexthopTypeIPv4:        backwardNexthopTypeIPv4,        // 2 -> 3
	nexthopTypeIPv4IFIndex: backwardNexthopTypeIPv4IFIndex, // 3 -> 4
	nexthopTypeIPv6:        backwardNexthopTypeIPv6,        // 4 -> 6
	nexthopTypeIPv6IFIndex: backwardNexthopTypeIPv6IFIndex, // 5 -> 7
	nexthopTypeBlackhole:   backwardNexthopTypeBlackhole,   // 6 -> 9
}

func (t nexthopType) toEach(version uint8) nexthopType {
	if version > 3 { // frr
		return t
	}
	if t == nexthopTypeIFIndex || t > nexthopTypeBlackhole { // 1 (common), 7, 8, 9 (out of map range)
		return t
	}
	backward, ok := nexthopTypeMap[t]
	if ok {
		return backward // converted value
	}
	return nexthopType(0) // error for conversion
}
func (n Nexthop) encode(version uint8, software Software, processFlag nexthopProcessFlag, message MessageFlag, apiFlag Flag) []byte {
	var buf []byte
	if processFlag&nexthopHasVrfID > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, n.VrfID)
		buf = append(buf, tmpbuf...) //frr: stream_putl(s, api_nh->vrf_id);
	}
	if processFlag&nexthopHasType > 0 {
		if n.Type == nexthopType(0) {
			n.Type = n.gateToType(version)
		}
		buf = append(buf, uint8(n.Type)) //frr: stream_putc(s, api_nh->type);
	}
	if processFlag&nexthopHasFlag > 0 || processFlag&nexthopHasOnlink > 0 {
		// frr7.1, 7.2 has onlink, 7.3 has flag
		buf = append(buf, n.flags) //frr: stream_putc(s, nh_flags);
	}

	nhType := n.Type
	if processFlag&nexthopProcessIPToIPIFindex > 0 {
		nhType = nhType.ipToIPIFIndex()
	}

	if nhType == nexthopTypeIPv4.toEach(version) ||
		nhType == nexthopTypeIPv4IFIndex.toEach(version) {
		//frr: stream_put_in_addr(s, &api_nh->gate.ipv4);
		buf = append(buf, n.Gate.To4()...)
	}

	return buf
}

func (b *IPRouteBody) decodeFromBytes(data []byte, version uint8, software Software) error {

	fmt.Printf("%x", data)
	return nil
}

func (b *IPRouteBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"route_type")
}

func (f MessageFlag) ToEach(version uint8, software Software) MessageFlag {
	if version > 4 { //zapi version 5, 6
		if f > messageNhg && (version == 5 ||
			(version == 6 && software.name == "frr" && software.version < 8)) { // except frr8
			return f >> 1
		}
		return f
	}
	if version < 4 { //zapi version 3, 2
		switch f {
		case MessageMTU:
			return 16
		case messageTag:
			return 32
		}
	}
	switch f { //zapi version 4
	case MessageDistance, MessageMetric, messageTag, MessageMTU, messageSRCPFX:
		return f << 1
	}
	return f
}
func (b *IPRouteBody) serialize(version uint8, software Software) ([]byte, error) {
	var buf []byte
	numNexthop := len(b.Nexthops)

	bufInitSize := 12 //type(1)+instance(2)+flags(4)+message(4)+safi(1), frr7.4&newer
	buf = make([]byte, bufInitSize)

	buf[0] = uint8(RouteBGP) //frr: stream_putc(s, api->type);
	//frr: stream_putw(s, api->instance);
	binary.BigEndian.PutUint16(buf[1:3], uint16(b.instance))
	//frr: stream_putl(s, api->flags);
	binary.BigEndian.PutUint32(buf[3:7], uint32(b.Flags))
	//frr7.5 and newer: stream_putl(s, api->message);
	binary.BigEndian.PutUint32(buf[7:11], uint32(5))
	buf[11] = uint8(b.Safi) //stream_putc(s, api->safi);
	b.Prefix.Family = familyFromPrefix(b.Prefix.Prefix)
	//frr: stream_putc(s, api->prefix.family);
	buf = append(buf, b.Prefix.Family)
	// only zapi version 5 (frr4.0.x) have evpn routes
	byteLen := (int(b.Prefix.PrefixLen) + 7) / 8
	buf = append(buf, b.Prefix.PrefixLen) //frr: stream_putc(s, api->prefix.prefixlen);
	buf = append(buf, b.Prefix.Prefix[:byteLen]...)

	processFlag := nexthopProcessFlagForIPRouteBody(version, software, false)
	tmpbuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tmpbuf, uint16(numNexthop))
	buf = append(buf, tmpbuf...) //frr: stream_putw(s, api->nexthop_num);
	for _, nexthop := range b.Nexthops {
		buf = append(buf, nexthop.encode(version, software, processFlag, b.Message, b.Flags)...)
	}

	metricbuf := make([]byte, 8)
	binary.BigEndian.PutUint32(metricbuf, b.Metric)
	binary.BigEndian.PutUint32(metricbuf, b.Mtu) // 最後の4byteはなんの4byteか分からない
	buf = append(buf, metricbuf...)
	return buf, nil
}
func (c *Client) SendRouteAdd() error {

	message := MessageNexthop
	if c.redistDefault > 0 {
		body := &IPRouteBody{
			Type:     RouteBGP,
			Flags:    0,
			Message:  message,
			Safi:     SafiUnicast,
			instance: 0,
			Prefix: Prefix{
				Prefix:    net.ParseIP("5.4.3.6").To4(),
				PrefixLen: uint8(32),
			},
			Nexthops: []Nexthop{
				{
					Gate: net.ParseIP("192.168.64.6"),
				},
			},
			Distance: uint8(0),
			Metric:   uint32(0),
			Mtu:      uint32(0),
		}
		return c.sendCommand(RouteAdd, 0, body) // body interface
	}
	return nil
}

func (b *ApiHeader) decodeApiHdr(data []byte) error {

	b.Len = binary.BigEndian.Uint16(data[0:2])
	b.Command = data[2]
	return nil
}

func netlinkSendRouteAdd(data []byte) error {

	//tt := binary.BigEndian.Uint32(data[4:8])

	var index uint8
	ipSrcBuf := make([]byte, 4)
	ipDstBuf := make([]byte, 4)

	copy(ipDstBuf, data[4:8])
	dstPrefix := net.IP(ipDstBuf).To4()

	copy(ipSrcBuf, data[9:13])
	srcPrefix := net.IP(ipSrcBuf).To4()
	fmt.Printf("%v", data)
	fmt.Printf("%v", dstPrefix.String())
	fmt.Printf("%v", srcPrefix.String())

	index = data[13]

	C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))
	return nil
}

func ReadAll(conn net.Conn) {
	defer conn.Close()

	hdr, err := unix_server.Read(conn)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("%v", hdr)
	hd := &ApiHeader{}
	hd.decodeApiHdr(hdr)

	switch hd.Command {
	case uint8(routeAdd):
		netlinkSendRouteAdd(hdr)

	}

}

func zebraClientInit() (*Client, error) {
	conn, err := net.Dial("unix", "/var/run/frr/zserv.api")

	if err != nil {
		log.Fatal(err)
	}

	outgoing := make(chan *Message)

	s := Software{
		name:    "frr",
		version: 8.1,
	}

	c := &Client{
		outgoing:      outgoing,
		redistDefault: RouteBGP,
		conn:          conn,
		Version:       6,
		Software:      s,
	}

	return c, nil

}

func (c *Client) zebraClientLoop() error {

	for {
		m, more := <-c.outgoing // c.send...で受け取るようになっている
		if more {
			b, err := m.serialize(c.Software)
			if err != nil {
				return nil
			}

			_, err = c.conn.Write(b)
			fmt.Printf("sendbuf:%v\n", b)
		}
	}

}

func main() {

	c, err := zebraClientInit()
	if err != nil {
		log.Fatal(err)
	}

	go c.zebraClientLoop()

	c.SendHello()
	c.SendRouteAdd()

	for {
		headerBuf, err := readAll(c.conn, int(HeaderSize(6)))
		if err != nil {
			log.Fatal(err)
		}

		hd := &Header{}
		err = hd.decodeFromBytes(headerBuf)
		if err != nil {
			log.Fatal(err)
		}
		bodyBuf, err := readAll(c.conn, int(hd.Len-HeaderSize(6)))
		if err != nil {
			log.Fatal(err)
		}
		log.Print("body:%v", bodyBuf)

	}

	//	listener, err := net.Listen("unix", "/tmp/test.sock")
	//	if err != nil {
	//		log.Fatal(err)
	//	}

	//	quit := make(chan os.Signal)
	//	signal.Notify(quit, os.Interrupt)
	//	go func() {
	//		<-quit
	//		os.Remove("/tmp/test.sock")
	//		os.Exit(1)
	//	}()
	//
	//	for {
	//		//
	//		conn, err := listener.Accept()
	//		//
	//		if err != nil {
	//			log.Fatal(err)
	//		}
	//		//
	//		go ReadAll(conn)
	//	}

	// main だけに書くな！

}
