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

func NetlinkSendStaticRouteAdd(dstPrefix string, srcPrefix string) error {

	C.ipv4_route_add(C.CString(dstPrefix), C.CString(srcPrefix), C.int(2))
	return nil
}

func NetlinkSendRouteAdd(data []byte) error {

	ipSrcBuf := make([]byte, 4)
	ipDstBuf := make([]byte, 4)

	copy(ipDstBuf, data[4:8])
	dstPrefix := net.IP(ipDstBuf).To4()
	copy(ipSrcBuf, data[9:13])
	srcPrefix := net.IP(ipSrcBuf).To4()
	fmt.Printf("%v", data)
	fmt.Printf("%v", dstPrefix.String())
	fmt.Printf("%v", srcPrefix.String())

	var index uint8
	index = data[13]

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

func NserverStart() error {

	listener, err := net.Listen("unix", "/tmp/test.sock")
	if err != nil {
		log.Fatal(err)
		return err
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		os.Remove("/tmp/test.sock")
		os.Exit(1)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			return err
		}
		go NeburaByteRead(conn)
	}

}
