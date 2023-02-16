package main

import (
	"log"

	"github.com/Enigamict/zebraland/pkg/nebura"
)

func Neburainit() {

	// start nebura
	err := nebura.NserverStart()

	if err != nil {
		log.Fatal(err)
	}

}

func main() {
	Neburainit()
}
