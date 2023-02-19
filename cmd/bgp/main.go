package main

import (
	"log"
	"net"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
)

func main() {

	c, err := config.BgpConfing("../../conf/bgp2.yaml")
	if err != nil {
		log.Fatal(err)
	}

	switch c.Select {
	case "nebura":
		for {
			p := nebura.PeerInit(c.As, net.ParseIP(c.Id).To4(), net.ParseIP(c.PeerPrefix.NeiAddr), c.Select)
			p.Run()
		}
		//p.PeerListen()
	case "zebra":
		for {
			p := nebura.PeerInit(c.As, net.ParseIP(c.Id).To4(), net.ParseIP(c.PeerPrefix.NeiAddr), c.Select)
			p.Run()
		}
	default:
		log.Printf("Plase select Routing Software to Zebra or Nebura\n")
	}

}
