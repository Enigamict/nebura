package bgp

import (
	"encoding/binary"
	"net"
)

const (
	bgpHederSize  = 19
	bgpMarkerSize = 16
)

type BgpMsg interface {
	writeTo()
}

type Peer struct {
	AS   uint16
	Conn net.Conn
}

type MessageHdr struct {
	Marker []byte
	Len    uint16
	Type   uint8
}

type Message struct {
	Hdr MessageHdr
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

type Update struct {
	NLRI net.IP
}

func PeerInit() *Peer {

	p := &Peer{
		AS: uint16(65000),
	}

	return p
}

func HdrInit(len uint16, bgpType uint8) ([]byte, error) {

	b := make([]byte, bgpHederSize)
	for i := 0; i < bgpMarkerSize; i++ {
		b[i] = 0xFF
	}

	binary.BigEndian.PutUint16(b[16:18], len)
	b[19] = bgpType
	return b, nil
}
