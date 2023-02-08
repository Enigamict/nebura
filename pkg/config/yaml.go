package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

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
	SrcPrefix string `yaml:"srcprefix"`
	DstPrefix string `yaml:"dstprefix"`
}

func ReadConfing() (Conf, error) {

	buf, err := ioutil.ReadFile("../../conf/static.yaml")
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
