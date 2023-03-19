package main

import "github.com/Enigamict/zebraland/pkg/nebura"

func main() {

	//var argconfig string
	//for i, v := range os.Args {
	//	fmt.Printf("args[%d] -> %s\n", i, v)
	//	argconfig = v
	//}

	//a, _ := config.ReadConfig(argconfig)
	n := nebura.NclientInit()
	//fmt.Printf("aa:%v:aa", a.IPPrefixAdd.DstAddr)
	//n.SendNclientIPv6Route(a.IPPrefixAdd.DstAddr, a.IPPrefixAdd.SrcAddr,
	//	uint8(a.IPPrefixAdd.DstAddrLen), uint8(a.IPPrefixAdd.Index))
	n.SendNclientXdp(0, "veth2")
	//n.SendNclientSeg6Add(a.Seg6Add.EncapAddr, a.Seg6Add.Segs)

	//n.SendNclientSRendAction(a.EndActionAdd.EndAction, a.EndActionAdd.NextHop,
	//	a.EndActionAdd.EncapAddr)
}
