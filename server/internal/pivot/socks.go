package pivot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 (RFC 1928). Only CONNECT is implemented: a pivot exists to reach a
// TCP service, and the other commands (BIND, UDP ASSOCIATE) have no meaning
// for a relayed stream.
//
// The proxy offers "no authentication" only. It binds to loopback by default
// and is created on demand by an operator RPC, so the operator console -- not
// the wire -- is the access control. A deployment that binds it to a routable
// address must put its own authentication in front of it.

const (
	socks5Version   = 0x05
	socks5NoAuth    = 0x00
	socks5NoAccept  = 0xFF
	socks5Connect   = 0x01
	socks5IPv4      = 0x01
	socks5Domain    = 0x03
	socks5IPv6      = 0x04
	socks5MaxDomain = 255
)

// SOCKS5 reply codes.
const (
	socks5Succeeded        = 0x00
	socks5GeneralFailure   = 0x01
	socks5NotAllowed       = 0x02
	socks5NetworkUnreach   = 0x03
	socks5HostUnreach      = 0x04
	socks5ConnRefused      = 0x05
	socks5TTLExpired       = 0x06
	socks5CommandNotSupp   = 0x07
	socks5AddrTypeNotSupp  = 0x08
)

// socks5Handshake performs the greeting and reads the CONNECT request.
//
// It returns the requested target. The reply is sent by the caller, because
// the connection is only worth reporting as successful once the agent has
// actually opened the far end.
func socks5Handshake(conn net.Conn) (string, int, error) {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: greeting: %w", err)
	}
	if head[0] != socks5Version {
		return "", 0, fmt.Errorf("socks5: unsupported version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, fmt.Errorf("socks5: methods: %w", err)
	}
	ok := false
	for _, m := range methods {
		if m == socks5NoAuth {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{socks5Version, socks5NoAccept})
		return "", 0, errors.New("socks5: no acceptable authentication method")
	}
	if _, err := conn.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return "", 0, fmt.Errorf("socks5: method selection: %w", err)
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: request: %w", err)
	}
	if req[0] != socks5Version {
		return "", 0, fmt.Errorf("socks5: unsupported request version %d", req[0])
	}
	if req[1] != socks5Connect {
		_ = socks5Reply(conn, socks5CommandNotSupp, "0.0.0.0", 0)
		return "", 0, fmt.Errorf("socks5: only CONNECT is supported (got %d)", req[1])
	}
	host, port, err := socks5ReadTarget(conn, req[3])
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// socks5ReadTarget reads the destination address and port.
func socks5ReadTarget(conn net.Conn, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case socks5IPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, fmt.Errorf("socks5: address: %w", err)
		}
		host = net.IP(buf).String()
	case socks5Domain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", 0, fmt.Errorf("socks5: domain length: %w", err)
		}
		if l[0] == 0 {
			return "", 0, errors.New("socks5: empty domain")
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, fmt.Errorf("socks5: domain: %w", err)
		}
		host = string(buf)
	case socks5IPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", 0, fmt.Errorf("socks5: address: %w", err)
		}
		host = net.IP(buf).String()
	default:
		_ = socks5Reply(conn, socks5AddrTypeNotSupp, "0.0.0.0", 0)
		return "", 0, fmt.Errorf("socks5: unsupported address type %d", atyp)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", 0, fmt.Errorf("socks5: port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	if port == 0 {
		return "", 0, errors.New("socks5: port 0")
	}
	return host, port, nil
}

// socks5Reply writes a SOCKS5 reply with an IPv4 bind address.
func socks5Reply(conn net.Conn, rep byte, bindAddr string, bindPort int) error {
	ip := net.ParseIP(bindAddr)
	if ip == nil || ip.To4() == nil {
		ip = net.IPv4zero
	}
	buf := make([]byte, 0, 10)
	buf = append(buf, socks5Version, rep, 0x00, socks5IPv4)
	buf = append(buf, ip.To4()...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(bindPort))
	buf = append(buf, port[:]...)
	_, err := conn.Write(buf)
	return err
}

// socks5Target renders a host:port pair for logs and events.
func socks5Target(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
