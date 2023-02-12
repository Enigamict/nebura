package main

import (
	"log"
	"net"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
)

func main() {

	c, err := config.BgpConfing("../../conf/bgp.yaml")
	if err != nil {
		log.Fatal(err)
	}

	p := nebura.PeerInit(65000, net.ParseIP(c.Id).To4(), net.ParseIP(c.PeerPrefix.NeiAddr))

	p.PeerListen()
}
