package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type BgpConf struct {
	BgpConf []PeerConf `yaml:"bgpconfig"`
}

type TcConf struct {
	TcConf []TcSetConf `yaml:"tcconfig"`
}

type TcSetConf struct {
	Qdisc string `yaml:"qdisc"`
	Ms    string `yaml:"ms"`
	Inter string `yaml:"inter"`
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
	Select      string     `yaml:"select"`
	Static      bool       `yaml:"static"`
	DeviceIndex int        `yaml:"DeviceIndex"`
	Prefix      ConfPrefix `yaml:"prefix"`
}

type ConfPrefix struct {
	SrcPrefix []string `yaml:"srcprefix"`
	DstPrefix string   `yaml:"dstprefix"`
}

func ReadConfing(pass string) ([]Conf, error) {

	buf, err := ioutil.ReadFile(pass)
	if err != nil {
		panic(err)
	}

	var d Data
	err = yaml.Unmarshal(buf, &d)
	if err != nil {
		panic(err)
	}

	return d.Conf[:], nil
}

func BgpConfing(pass string) (PeerConf, error) {

	buf, err := ioutil.ReadFile(pass)
	if err != nil {
		panic(err)
	}

	var d BgpConf
	err = yaml.Unmarshal(buf, &d)
	if err != nil {
		panic(err)
	}

	return d.BgpConf[0], nil
}

func TcConfing(pass string) (TcSetConf, error) {

	buf, err := ioutil.ReadFile(pass)
	if err != nil {
		panic(err)
	}

	var d TcConf
	err = yaml.Unmarshal(buf, &d)
	if err != nil {
		panic(err)
	}

	return d.TcConf[0], nil
}
