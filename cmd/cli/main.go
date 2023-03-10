package main

import (
	"fmt"
	"net"
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
	n := nebura.NclientInit("static")
	fmt.Printf("%v", a)
	n.SendNclientIPv6RouteAdd(net.ParseIP(a.IPPrefixAdd.DstAddr), net.IP(a.IPPrefixAdd.SrcAddr), 64)

}
