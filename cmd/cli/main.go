package main

import (
	"fmt"
	"os"

	"github.com/Enigamict/zebraland/pkg/config"
)

func main() {

	var argconfig string
	for i, v := range os.Args {
		fmt.Printf("args[%d] -> %s\n", i, v)
		argconfig = v
	}

	a, _ := config.ReadConfig(argconfig)
	fmt.Printf("%v", a)
}
