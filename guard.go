package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
)

var (
	tcpPacketTypeNull    string = "TCP NULL scan"
	tcpPacketTypeXMAS    string = "TCP XMAS scan"
	tcpPacketTypeSYN     string = "TCP SYN/Normal scan"
	tcpPacketTypeUnknown string = "Unknown Type: TCP Packet Flags(FIN,SYN,RST,PSH,ACK,URG): %d"
)

var (
	sockAddr syscall.SockaddrInet4
	serverIp = net.ParseIP("0.0.0.0").To4()
)

func init() {
	copy(sockAddr.Addr[:], serverIp[:])
}

// if port is in used
// golang auto set SO_REUSEADDR when listen a port
/*
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
*/

func smartVerifyTCP(port int) bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	sockAddr.Port = port
	err = syscall.Bind(fd, &sockAddr)
	syscall.Close(fd)
	if err != nil {
		return true
	}
	return false
}

func reportPacketType(flags uint8) *string {
	if flags == 0 {
		return &tcpPacketTypeNull
	} else if flags&(FIN|URG|PSH) == (FIN | URG | PSH) {
		return &tcpPacketTypeXMAS
	} else if flags == SYN {
		return &tcpPacketTypeSYN
	} else {
		packetType := fmt.Sprintf(tcpPacketTypeUnknown, flags)
		return &packetType
	}
}

// tcp guard
func tcpGuard() {
	buf := make([]byte, 1024)
	var tcp TCPHeader
	for {
		conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: serverIp})
		if err != nil {
			log.Print(err)
			continue
		}

		numRead, remoteAddr, err := conn.ReadFrom(buf)
		// close immedately
		conn.Close()
		if err != nil {
			continue
		}

		NewTCPHeader(buf[:numRead], &tcp)
		/*nmap: Page 65 of RFC 793 says that “if the [destination] port state is
		CLOSED .... an incoming segment not containing a RST causes a RST to be
		sent in response.”  Then the next page discusses packets sent to open
		ports without the SYN, RST, or ACK bits set, stating that: “you are
		unlikely to get here, but if you do, drop the segment, and return.”
		*/
		if tcp.HasFlag(RST) || tcp.HasFlag(ACK) {
			continue
		}

		port := tcp.Destination
		log.Printf("port %d, flags:%d", port, tcp.Ctrl)
		if smartVerifyTCP(int(port)) {
			continue
		}
		log.Printf("attackalert: %s from host: %s to TCP port: %d",
			*reportPacketType(tcp.Ctrl), remoteAddr.String(), port)
	}
}

func main() {
	tcpGuard()
}
