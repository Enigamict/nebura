package unix_server

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

// HDR + TypeBody
// HDR HdrLen(uint16_t) Type(uint8_t)
// Type Route Add : Netlink mode

type Echo struct {
	Length int
	Data   []byte
}

func (e *Echo) Write(c net.Conn) error {
	data := make([]byte, 0, 4+e.Length)

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(e.Length))
	data = append(data, buf...)

	w := bytes.Buffer{}
	err := binary.Write(&w, binary.BigEndian, e.Data)
	if err != nil {
		return err
	}

	data = append(data, w.Bytes()...)

	_, err = c.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func Read(c net.Conn) ([]byte, error) {
	buf := make([]byte, 14)

	_, err := io.ReadFull(c, buf)

	if err != nil {
		return nil, err
	}

	return buf, nil
}
