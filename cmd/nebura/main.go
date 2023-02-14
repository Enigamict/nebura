package main

import (
	"log"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
	"github.com/Enigamict/zebraland/pkg/zebra"
)

func main() {

	// ZebraかNeburaを選択する
	s, err := config.ReadConfing("../../conf/static.yaml")

	if err != nil {
		log.Fatal(err)
	}

	switch s.Select {
	case "nebura":
		switch s.Static {
		case true:
			err := nebura.NetlinkSendStaticRouteAdd(s.Prefix.SrcPrefix, s.Prefix.SrcPrefix, uint8(s.DeviceIndex))

			if err != nil {
				log.Fatal(err)
			}
		default:
			err := nebura.NserverStart()

			if err != nil {
				log.Fatal(err)
			}
		}
	case "zebra":
		c, err := zebra.ZebraClientInit()

		if err != nil {
			log.Fatal(err)
		}

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
