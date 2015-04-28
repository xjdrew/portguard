/*
	date: 2015-04-28
	author: xjdrew
*/
package main

import (
	"bytes"
	"encoding/binary"
)

type UDPHeader struct {
	Source      uint16
	Destination uint16
	Length      uint16
	Checksum    uint16
}

func NewUDPHeader(data []byte, udp *UDPHeader) *UDPHeader {
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &udp.Source)
	binary.Read(r, binary.BigEndian, &udp.Destination)
	binary.Read(r, binary.BigEndian, &udp.Length)
	binary.Read(r, binary.BigEndian, &udp.Checksum)
	return udp
}
