package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
)

func main() {

	// 消す
	var bgpconfig string
	for i, v := range os.Args {
		fmt.Printf("args[%d] -> %s\n", i, v)
		bgpconfig = v
	}

	c, err := config.BgpConfing(bgpconfig)
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
