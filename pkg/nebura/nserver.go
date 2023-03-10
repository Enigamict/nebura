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

var NeburaHdrSize uint16

var r Rib = RibInit()
var RibCount = 0

type (
	ClientEvent interface {
		NecliEvent(*Nserver) error
	}

	NservClientRead struct {
		hdr  []byte
		data []byte
	}
	NservClientWrite struct{}
	NservMsgSend     struct { // いずれ消す
		api  ApiHeader
		data []byte
	}
)

const (
	staticRouteAdd  uint8 = 1
	bgpRouteAdd     uint8 = 2
	bgpIPv6RouteAdd uint8 = 3
	bgpRIBFind      uint8 = 4
	tcNetem         uint8 = 5
)

type RIBPrefix struct {
	PrefixLen       uint8
	Prefix          net.IP
	Nexthop         net.IP
	Index           uint8
	RoutingProtocol string
}

type Rib struct {
	mu     *sync.Mutex
	Preifx map[int]RIBPrefix
}

type Nserver struct {
	lis        net.Listener
	Conn       net.Conn
	ceventChan chan ClientEvent
	Rib        Rib
}

func (n NservMsgSend) NecliEvent(ns *Nserver) error {

	switch n.api.Type {
	case staticRouteAdd:
		NetlinkSendStaticRouteAdd(n.data)
	case bgpRouteAdd:
		ns.NetlinkSendRouteAdd(n.data)
	case bgpIPv6RouteAdd:
		NetlinkSendIPv6RouteAdd(n.data)
	case bgpRIBFind:
		ns.NclientRibFind()
	case tcNetem:
		ns.NetlinkSendTcNetem(n.data)
	default:
		log.Printf("not type")
	}

	return nil
}

func (n NservClientRead) NecliEvent(ns *Nserver) error {
	hd := &ApiHeader{}
	hd.DecodeApiHdr(n.hdr)

	ns.ceventChan <- NservMsgSend{*hd, n.data}
	return nil
}

func (n *Nserver) ClientSendEvent() error {

	for {
		select {
		case e := <-n.ceventChan:
			if err := e.NecliEvent(n); err != nil {
				return err
			}
		}
	}
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

func v6prefixPadding(data []byte) net.IP {
	return net.IP(data).To16()
}

func (r *Rib) RibShow() {
	fmt.Printf("RIB SHOW: %v\n", r.Preifx)
}

func (r *Rib) RibFind(prefix net.IP) bool {

	defer r.mu.Lock()
	r.mu.Unlock()
	var p bool
	for _, v := range r.Preifx {
		p = v.Prefix.Equal(prefix)
	}

	return p
}

func (r *Rib) RibAdd(addRoute RIBPrefix) error { // Addだけで良い、Ribと決まっているから

	defer r.mu.Unlock()
	r.mu.Lock()

	if r.RibFind(addRoute.Prefix) {
		log.Printf("RIB Already in prefix")

		return nil
	}

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

func (n *Nserver) NetlinkSendTcNetem(data []byte) error {

	s := fmt.Sprintf("%s", data[0:5])
	//index := uint8(data[5])
	fmt.Printf("%s", s)

	//C.tc_netem_add(C.int(index), C.CString(s))
	return nil
}

func (n *Nserver) NetlinkSendRouteAdd(data []byte) error {

	fmt.Printf("%v", data)
	dstPrefix := prefixPadding(data[1:5])
	srcPrefix := prefixPadding(data[6:10])

	index, err := NexthopPrefixIndex(srcPrefix.String())

	if err != nil {
		return nil
	}

	a := RIBPrefix{
		Prefix:          dstPrefix,
		PrefixLen:       uint8(data[8]),
		Nexthop:         srcPrefix,
		Index:           uint8(index),
		RoutingProtocol: "BGP",
	}

	r.RibAdd(a)

	//C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))
	return nil
}

func NetlinkSendIPv6RouteAdd(data []byte) error {

	dstPrefix := v6prefixPadding(data[0:16])
	C.ipv6_route_add(C.CString(dstPrefix.String()), C.int(42))
	return nil
}

func (b *ApiHeader) DecodeApiHdr(data []byte) error {

	b.Len = binary.BigEndian.Uint16(data[0:2])
	b.Type = data[2]
	return nil
}

func (n *Nserver) NserverRead(data []byte) {
	hd := &ApiHeader{}
	hd.DecodeApiHdr(data)

	switch hd.Type {
	case staticRouteAdd:
		NetlinkSendStaticRouteAdd(data)
	case bgpRouteAdd:
		n.NetlinkSendRouteAdd(data)
	case bgpIPv6RouteAdd:
		NetlinkSendIPv6RouteAdd(data)
	case bgpRIBFind:
		n.NclientRibFind()
	case tcNetem:
		n.NetlinkSendTcNetem(data)
	default:
		log.Printf("not type")
	}
}

func (n *Nserver) NeburaRead() error {

	log.Printf("Msg Read...\n")
	var header [3]byte
	_, err := io.ReadFull(n.Conn, header[:])

	if err != nil {
		log.Printf("err read")
		return nil
	}

	nsize := binary.BigEndian.Uint16(header[0:2])
	buf := make([]byte, nsize-3)

	if _, err := io.ReadFull(n.Conn, buf); err != nil {
		return nil
	}

	go n.ClientSendEvent()
	n.ceventChan <- NservClientRead{header[:], buf}

	//n.NserverRead(buf)
	return nil
}

func (n *Nserver) NclientRibFind() {

	var buf []byte

	for _, v := range r.Preifx {
		buf = append(buf, v.Prefix...)
		log.Printf("%v", buf)
	}

	n.Conn.Write(buf)
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

func NserverStart() {
	listener, err := net.Listen("unix", "/tmp/test.sock")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Nebura Server start...\n")

	go signalNotify()

	n := &Nserver{
		lis:        listener,
		ceventChan: make(chan ClientEvent, 10),
	}

	for {
		var errr error
		n.Conn, errr = n.lis.Accept()
		log.Printf("Nebura Accept...\n")
		if errr != nil {
			log.Fatal(err)
		}
		n.NeburaRead()
	}

	//TestCallBackEvent(TestSendEvent)
	//n.eventChan <- NservAccept{}
	//n.ServerSendEvent()
}
