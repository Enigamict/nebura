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
	SrcAddr    string `yaml:"srcaddr"`
	DstAddr    string `yaml:"dstaddr"`
	DstAddrLen int    `yaml:"dstaddr_len"`
	Index      int    `yaml:"index"`
}

type Seg6Add struct {
	Segs      string `yaml:"segs"`
	EncapAddr string `yaml:"encapaddr"`
}

type EndActionAdd struct {
	EndAction string `yaml:"endaction"`
	EncapAddr string `yaml:"encapaddr"`
	NextHop   string `yaml:"nexthop"`
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

type Data struct {
	Conf []Conf `yaml:"config"`
}

type Conf struct {
	Select       string       `yaml:"select"`
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
