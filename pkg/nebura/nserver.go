package nebura

/*
#cgo LDFLAGS: -L. -lipv4add
#include "libnetlink.h"
#include "ipv4add.h"
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

const NeburaHdrSize = 14

const (
	testHello      uint8 = 0
	staticRouteAdd uint8 = 1
	bgpRouteAdd    uint8 = 2
)

type ApiHeader struct {
	Len  uint16
	Type uint8
}

type RIBPrefix struct {
	PrefixLen uint8
	Prefix    net.IP
}

type Rib struct {
	mu     *sync.Mutex
	Preifx map[int]*RIBPrefix
}

func NetlinkSendStaticRouteAdd(dstPrefix string, srcPrefix string, index uint8) error {

	C.ipv4_route_add(C.CString(dstPrefix), C.CString(srcPrefix), C.int(index))

	return nil
}

func prefixPadding(data []byte) net.IP {
	return net.IP(data).To4()
}

func (r *Rib) RibShow() {

	for k, v := range r.Preifx {
		fmt.Printf("key: %v, value: %v\n", k, v)
	}
}

var RibCount = 0

func (r *Rib) RibAdd(addRoute *RIBPrefix) error {

	defer r.mu.Unlock()
	r.mu.Lock()

	RibCount++

	for i := 0; i < RibCount; i++ {
		r.Preifx[i] = addRoute
	}

	return nil
}

func RibInit() *Rib {
	return &Rib{
		mu:     new(sync.Mutex),
		Preifx: make(map[int]*RIBPrefix),
	}
}

func NetlinkSendRouteAdd(data []byte) error {

	dstPrefix := prefixPadding(data[4:8])
	srcPrefix := prefixPadding(data[9:13])

	//index := int(data[13])

	r := RibInit()
	a := &RIBPrefix{
		Prefix:    dstPrefix,
		PrefixLen: uint8(32),
	}
	fmt.Printf("%v", dstPrefix.String())
	fmt.Printf("%v", srcPrefix.String())

	r.RibAdd(a)

	r.RibShow()

	//C.ipv4_route_add(C.CString(dstPrefix.String()), C.CString(srcPrefix.String()), C.int(index))
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
		NetlinkSendRouteAdd(data)
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

	go signalNotify()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			return err
		}
		go NeburaByteRead(conn)
	}

}
