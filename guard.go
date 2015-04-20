package main

import (
	"fmt"
	"log"
	"net"
)

var serverIp = net.ParseIP("0.0.0.0")

// if port is in used
func smartVerifyTCP(port int) bool {
	addr := &net.TCPAddr{
		IP:   serverIp,
		Port: port,
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return true
	}
	ln.Close()
	return false
}

func reportPacketType(flags uint8) string {
	if flags == 0 {
		return "TCP NULL scan"
	} else if flags&(FIN|URG|PSH) == (FIN | URG | PSH) {
		return "TCP XMAS scan"
	} else if flags == SYN {
		return "TCP SYN/Normal scan"
	} else {
		return fmt.Sprintf("Unknown Type: TCP Packet Flags(FIN,SYN,RST,PSH,ACK,URG): %d", flags)
	}
}

func filterPacket(addr net.Addr, data []byte) {
	tcp := NewTCPHeader(data)
	// portsentry: check for an ACK/RST to weed out established connections in case the user
	// is monitoring high ephemeral port numbers
	if tcp.HasFlag(RST) || tcp.HasFlag(ACK) {
		return
	}

	port := tcp.Destination
	if smartVerifyTCP(int(port)) {
		return
	}
	log.Printf("attackalert: %s from host: %s to TCP port: %d",
		reportPacketType(tcp.Ctrl), addr.String(), port)
}

func main() {
	netProto := "ip4:tcp"
	addr, err := net.ResolveIPAddr(netProto, "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024)
	for {
		conn, err := net.ListenIP(netProto, addr)
		if err != nil {
			log.Print(err)
			continue
		}

		numRead, remoteAddr, err := conn.ReadFrom(buf)
		conn.Close()
		if err != nil {
			continue
		}

		filterPacket(remoteAddr, buf[:numRead])
	}
}
