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

	switch c.Select {
	case "nebura":
		p := nebura.PeerInit(c.As, net.ParseIP(c.Id).To4(), net.ParseIP(c.PeerPrefix.NeiAddr), c.Select)
		p.PeerListen()
	case "zebra":
		p := nebura.PeerInit(c.As, net.ParseIP(c.Id).To4(), net.ParseIP(c.PeerPrefix.NeiAddr), c.Select)
		p.PeerListen()
	default:
		log.Printf("Plase select Routing Software to Zebra or Neburan\n")
	}
}
