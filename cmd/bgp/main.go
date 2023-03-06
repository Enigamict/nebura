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

	c, err := config.ReadConfig(bgpconfig)
	if err != nil {
		log.Fatal(err)
	}

	for {
		p := nebura.PeerInit(c.BgpConf.As, net.ParseIP(c.BgpConf.Id).To4(), net.ParseIP(c.BgpConf.PeerPrefix.NeiAddr).To4(), c.Select)
		p.Run()
	}
}
