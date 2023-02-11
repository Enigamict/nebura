package main

import (
	"net"

	"github.com/Enigamict/zebraland/pkg/nebura"
)

func main() {

	p := nebura.PeerInit(65000, net.ParseIP("10.255.3.4").To4(), net.ParseIP("10.255.3.1"))

	p.PeerListen()
}
