package main

import (
	"fmt"
	"os"

	"github.com/Enigamict/zebraland/pkg/config"
	"github.com/Enigamict/zebraland/pkg/nebura"
)

func main() {

	var argconfig string
	for i, v := range os.Args {
		fmt.Printf("args[%d] -> %s\n", i, v)
		argconfig = v
	}

	a, _ := config.ReadConfig(argconfig)
	n := nebura.NclientInit()
	fmt.Printf("aa:%v:aa", a.IPPrefixAdd.DstAddr)
	n.SendNclientIPv6RouteAdd(a.IPPrefixAdd.DstAddr, a.IPPrefixAdd.SrcAddr,
		uint8(a.IPPrefixAdd.DstAddrLen), uint8(a.IPPrefixAdd.Index))
}
