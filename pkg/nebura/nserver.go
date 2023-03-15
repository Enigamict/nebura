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

var r Rib = Init()
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
	NservMsgSend     struct {
		api  ApiHeader
		data []byte
	}
)

const (
	staticRouteAdd uint8 = 1
	bgpRouteAdd    uint8 = 2
	IPv6RouteAdd   uint8 = 3
	segsAdd        uint8 = 4
	srEndAction    uint8 = 5
	tcNetem        uint8 = 6
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
	Preifx map[string][]RIBPrefix
}

type Nserver struct {
	lis        net.Listener
	Conn       net.Conn
	ceventChan chan ClientEvent
	Rib        Rib
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

func (n NservMsgSend) NecliEvent(ns *Nserver) error {

	switch n.api.Type {
	case staticRouteAdd:
		NetlinkSendStaticRouteAdd(n.data)
	case bgpRouteAdd:
		NetlinkSendRouteAdd(n.data)
	case IPv6RouteAdd:
		NetlinkSendIPv6RouteAdd(n.data)
	case segsAdd:
		NetlinkSendSegsAdd(n.data)
	case srEndAction:
		NetlinkSendSrEndAction(n.data)
	case tcNetem:
		NetlinkSendTcNetem(n.data)
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

func NetlinkSendStaticRouteAdd(data []byte) error {
	//dstPrefix := prefixPadding(data[4:8])
	//srcPrefix := prefixPadding(data[9:13])

	//index, _ := NexthopPrefixIndex(srcPrefix.String())

	//C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))

	return nil
}

func NetlinkSendSegsAdd(data []byte) error {

	fmt.Printf("%v", data[4:20])
	encapPrefix := prefixPadding(data[0:4])
	segs := v6prefixPadding(data[4:20])
	fmt.Printf("%s", encapPrefix.String())
	fmt.Printf("%s", segs.String())
	C.seg6_route_add(C.CString(encapPrefix.String()), C.CString(segs.String()))
	return nil
}

const EndDX4 uint8 = 6

func NetlinkSendSrEndAction(data []byte) error {

	fmt.Printf("data:%v", data[17:21])
	endAction := uint8(data[0])
	encapPrefix := v6prefixPadding(data[1:17])
	dstPrefix := prefixPadding(data[17:21])
	switch endAction {
	case EndDX4: // indexをなんとかする
		C.seg6_end_aciton(C.CString(encapPrefix.String()), C.CString(dstPrefix.String()))
	}
	return nil
}

func prefixPadding(data []byte) net.IP {
	return net.IP(data).To4()
}

func v6prefixPadding(data []byte) net.IP {
	return net.IP(data).To16()
}

func (r *Rib) RibShow() {

	fmt.Printf("RIB SHOW\n")

	for _, v := range r.Preifx["BGP"] {
		fmt.Printf("%s: %s/%d via %s\n", v.RoutingProtocol, v.Prefix.String(),
			v.PrefixLen, v.Nexthop.String())
	}

}

func (r *Rib) RibFind(prefix net.IP, routeType string) bool {
	defer r.mu.Lock()
	r.mu.Unlock()
	var p bool
	for _, v := range r.Preifx[routeType] {
		p = v.Prefix.Equal(prefix)
	}
	return p
}

func (r *Rib) Add(addRoute RIBPrefix) error { // Addだけで良い、Ribと決まっているから

	defer r.mu.Unlock()
	r.mu.Lock()

	if r.RibFind(addRoute.Prefix, "BGP") { // BGP以外も入る
		log.Printf("RIB Already in prefix")

		return nil
	}

	r.Preifx[addRoute.RoutingProtocol] = append(r.Preifx[addRoute.RoutingProtocol],
		addRoute)

	r.RibShow()

	RibCount++
	return nil
}

func Init() Rib {
	return Rib{
		mu:     new(sync.Mutex),
		Preifx: make(map[string][]RIBPrefix, 1000),
	}
}

func NetlinkSendTcNetem(data []byte) error {

	s := fmt.Sprintf("%s", data[0:5])
	//index := uint8(data[5])
	fmt.Printf("%s", s)

	//C.tc_netem_add(C.int(index), C.CString(s))
	return nil
}

func NetlinkSendRouteAdd(data []byte) error {

	dstPrefixLen := uint8(data[0])
	dstPrefix := prefixPadding(data[1:5])
	srcPrefix := prefixPadding(data[6:10])

	index, err := NexthopPrefixIndex(srcPrefix.String())

	if err != nil {
		return nil
	}

	a := RIBPrefix{
		Prefix:          dstPrefix,
		PrefixLen:       uint8(data[0]),
		Nexthop:         srcPrefix,
		Index:           uint8(index),
		RoutingProtocol: "BGP",
	}

	r.Add(a)

	C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()),
		C.int(index), C.int(dstPrefixLen))
	return nil
}

func NetlinkSendIPv6RouteAdd(data []byte) error {

	// TODO /64 /128 interfaceだけで入れたい場合を考える

	fmt.Printf("data%v", data)
	dstPrefix := v6prefixPadding(data[0:16])

	srcPrefix := v6prefixPadding(data[17:33])
	fmt.Printf("prefix:%s", srcPrefix.String())
	fmt.Printf("prefix:%s", dstPrefix.String())
	C.ipv6_route_add(C.CString(srcPrefix.String()),
		C.CString(dstPrefix.String()), C.int(40), C.int(128))
	return nil
}

func (b *ApiHeader) DecodeApiHdr(data []byte) error {

	b.Len = binary.BigEndian.Uint16(data[0:2])
	b.Type = data[2]
	return nil
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

	return nil
}

//func (n *Nserver) NclientRibFind() {
//
//	var buf []byte
//
//	for _, v := range r.Preifx {
//		buf = append(buf, v.Prefix...)
//		log.Printf("%v", buf)
//	}
//
//	n.Conn.Write(buf)
//}

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
