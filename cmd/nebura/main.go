package main

import (
	"log"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
	"github.com/Enigamict/zebraland/pkg/zebra"
)

func main() {

	// ZebraかNeburaを選択する
	s, err := config.ReadConfing()

	if err != nil {
		log.Fatal(err)
	}

	switch s.Select {
	case "nebura":
		if s.Static {
			err := nebura.NetlinkSendStaticRouteAdd(s.Prefix.DstPrefix, s.Prefix.SrcPrefix)

			if err != nil {
				log.Fatal(err)
			}
		}
		err := nebura.NserverStart()

		if err != nil {
			log.Fatal(err)
		}
	case "zebra":
		c, err := zebra.ZebraClientInit()

		if err != nil {
			log.Fatal(err)
		}

		go c.ZebraClientLoop()
		c.SendHello()
		c.SendRouteAdd()

		for {
			headerBuf, err := zebra.ZebraByteRead(c.Conn, int(zebra.ZebraHeaderSize))
			if err != nil {
				log.Fatal(err)
			}

			log.Print("body:%v", headerBuf)

		}
	default:
		log.Printf("Zebra or Nebura")
	}

}
