package nebura

/*
#cgo LDFLAGS: -L. -lnetlink_code
#include "libnetlink.h"
#include "netlink_code.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
)

type ApiType uint8

const NeburaHdrSize = 13

var r Rib = RibInit()

type (
	NeburaEvent interface {
		Loop(*Peer) error
	}
)

const (
	testHello       uint8 = 0
	staticRouteAdd  uint8 = 1
	bgpRouteAdd     uint8 = 2
	bgpIPv6RouteAdd uint8 = 3
)

type RIBPrefix struct {
	PrefixLen       uint8
	Prefix          net.IP
	Nexthop         net.IP
	Index           uint8
	RoutingProtocol string
	Prefix2         *net.IPNet
}

type Rib struct {
	mu     *sync.Mutex
	Preifx map[int]RIBPrefix
}

type Nserver struct {
	Conn net.Conn
	Rib  Rib
}

func NexthopPrefixIndex(prefix string) (int, error) {

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
		return 0, nil
	}

	var b bool = false
	var index int

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Fatal(err)
			continue
		}

		for _, a := range addrs {
			if !b {
				_, ipnet, _ := net.ParseCIDR(a.String())
				ip := net.ParseIP(prefix)
				b = ipnet.Contains(ip)
				index = i.Index
				break
			}

		}

	}

	return index, nil
}

func NetlinkSendStaticRouteAdd(data []byte) error {
	dstPrefix := prefixPadding(data[4:8])
	srcPrefix := prefixPadding(data[9:13])

	index, _ := NexthopPrefixIndex(srcPrefix.String())

	C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))

	return nil
}

func prefixPadding(data []byte) net.IP {
	return net.IP(data).To4()
}

var RibCount = 0

func (r *Rib) RibShow() {
	fmt.Printf("RIB SHOW: %v\n", r.Preifx)
}

func (r *Rib) RibFind(prefix net.IP) bool {

	defer r.mu.Unlock()
	r.mu.Lock()
	var p bool
	for _, v := range r.Preifx {
		p = v.Prefix2.IP.Equal(prefix)
	}

	return p
}

func (r *Rib) RibAdd(addRoute RIBPrefix) error {

	defer r.mu.Unlock()
	r.mu.Lock()

	r.Preifx[RibCount] = addRoute
	RibCount++
	r.RibShow()
	return nil
}

func RibInit() Rib {
	return Rib{
		mu:     new(sync.Mutex),
		Preifx: make(map[int]RIBPrefix),
	}
}

func NetlinkSendRouteAdd(data []byte) error {

	dstPrefix := prefixPadding(data[4:8])
	srcPrefix := prefixPadding(data[9:13])

	index, _ := NexthopPrefixIndex(srcPrefix.String())

	a := RIBPrefix{
		Prefix:          dstPrefix,
		PrefixLen:       uint8(data[8]),
		Nexthop:         srcPrefix,
		Index:           uint8(index),
		RoutingProtocol: "BGP",
	}

	r.RibAdd(a)
	C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))
	return nil
}

func NetlinkSendIPv6RouteAdd(data []byte) error {

	dstPrefix := prefixPadding(data[4:8])
	srcPrefix := prefixPadding(data[9:13])

	index, _ := NexthopPrefixIndex(srcPrefix.String())

	C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))
	return nil
}

func (b *ApiHeader) DecodeApiHdr(data []byte) error {

	b.Len = binary.BigEndian.Uint16(data[0:2])
	b.Type = data[2]
	return nil
}

func NeburaRead(c net.Conn) ([]byte, error) {
	buf := make([]byte, NeburaHdrSize)
	_, err := io.ReadFull(c, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func neburaEvent(h *ApiHeader, data []byte) {

	switch h.Type {
	case staticRouteAdd:
		NetlinkSendStaticRouteAdd(data)
	case bgpRouteAdd:
		NetlinkSendRouteAdd(data)
	case bgpIPv6RouteAdd:
		NetlinkSendIPv6RouteAdd(data)
	default:
		log.Printf("not type")
	}
}

func NeburaByteRead(conn net.Conn) {
	defer conn.Close()

	hdr, err := NeburaRead(conn)

	if err != nil {
		log.Println(err)
	}

	hd := &ApiHeader{}

	hd.DecodeApiHdr(hdr)

	neburaEvent(hd, hdr)
}

func signalNotify() {
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		os.Remove("/tmp/test.sock")
		os.Exit(1)
	}()

}

func NserverStart() error {
	listener, err := net.Listen("unix", "/tmp/test.sock")
	if err != nil {
		log.Fatal(err)
		return err
	}
	log.Printf("Nebura Server start...\n")

	go signalNotify()

	for {
		conn, err := listener.Accept()
		log.Printf("Nebura Server Sock number %d...\n", conn)
		if err != nil {
			log.Fatal(err)
			return err
		}

		go NeburaByteRead(conn)
	}

}
