package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type TcSetConf struct {
	Qdisc string `yaml:"qdisc"`
	Ms    string `yaml:"ms"`
	Inter string `yaml:"inter"`
}

type IPPrefixAdd struct {
	SrcAddr string `yaml:"srcaddr"`
	DstAddr string `yaml:"dstaddr"`
}

type Seg6Add struct {
	Segs    string `yaml:"segs"`
	DstAddr string `yaml:"dstaddr"`
}

type EndActionAdd struct {
	EndAction string `yaml:"endaction"`
	DstAddr   string `yaml:"dstaddr"`
}

type PeerConf struct {
	Select     string     `yaml:"select"`
	Id         string     `yaml:"id"`
	As         uint16     `yaml:"as"`
	PeerPrefix PeerPrefix `yaml:"peer"`
}

type PeerPrefix struct {
	NeiAddr string `yaml:"neiaddr"`
}
type StaticConf struct {
	IPPrefixAdd  IPPrefixAdd  `yaml:"ipconfig"`
	Seg6Add      Seg6Add      `yaml:"srv6config"`
	EndActionAdd EndActionAdd `yaml:"srv6endconfig"`
	TcConf       TcSetConf    `yaml:"tcconfig"`
}

type Data struct {
	Conf []Conf `yaml:"config"`
}

type Conf struct {
	Select       string       `yaml:"select"`
	FibInstall   bool         `yaml:"fib_install"`
	IPPrefixAdd  IPPrefixAdd  `yaml:"ipconfig"`
	Seg6Add      Seg6Add      `yaml:"srv6config"`
	EndActionAdd EndActionAdd `yaml:"srv6endconfig"`
	TcConf       TcSetConf    `yaml:"tcconfig"`
	BgpConf      PeerConf     `yaml:"bgpconfig"`
}

func ReadConfig(pass string) (Conf, error) {
	buf, err := ioutil.ReadFile(pass)
	if err != nil {
		panic(err)
	}

	var d Data
	err = yaml.Unmarshal(buf, &d)
	if err != nil {
		panic(err)
	}
	return d.Conf[0], nil
}
