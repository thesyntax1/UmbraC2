package pivot

import (
	"crypto/subtle"
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
// The proxy offers "no authentication" when the operator did not configure
// a user, and the username and password method (RFC 1929) when it did.  It
// binds to loopback by default and is created on demand by an operator RPC,
// so the operator console -- not the wire -- is the access control.  A
// deployment that binds it to a routable address must configure the
// credentials as well.

const (
	socks5Version   = 0x05
	socks5NoAuth    = 0x00
	socks5UserPass  = 0x02
	socks5NoAccept  = 0xFF
	socks5Connect   = 0x01
	socks5IPv4      = 0x01
	socks5Domain    = 0x03
	socks5IPv6      = 0x04
	socks5MaxDomain = 255
	socks5MaxUser   = 255
	socks5MaxPass   = 255
)

// SOCKS5 reply codes.
const (
	socks5Succeeded       = 0x00
	socks5GeneralFailure  = 0x01
	socks5NotAllowed      = 0x02
	socks5NetworkUnreach  = 0x03
	socks5HostUnreach     = 0x04
	socks5ConnRefused     = 0x05
	socks5TTLExpired      = 0x06
	socks5CommandNotSupp  = 0x07
	socks5AddrTypeNotSupp = 0x08
)

// socks5Handshake performs the greeting and reads the CONNECT request.
//
// It returns the requested target. The reply is sent by the caller, because
// the connection is only worth reporting as successful once the agent has
// actually opened the far end.
func socks5Handshake(conn net.Conn, user, password string) (string, int, error) {
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
	// The method the server wants: the credentials when the operator
	// configured them, the open door when they did not.
	want := byte(socks5NoAuth)
	if user != "" {
		want = socks5UserPass
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{socks5Version, socks5NoAccept})
		return "", 0, errors.New("socks5: no acceptable authentication method")
	}
	if _, err := conn.Write([]byte{socks5Version, want}); err != nil {
		return "", 0, fmt.Errorf("socks5: method selection: %w", err)
	}
	if want == socks5UserPass {
		if err := socks5Authenticate(conn, user, password); err != nil {
			return "", 0, err
		}
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

// socks5Reply writes a SOCKS5 reply with the bind address of the listener.
//
// The address family of the listener is kept: a proxy that listens on the
// IPv6 loopback answers with an IPv6 address, so a client on an IPv6-only
// network is not told about an address it cannot use.
func socks5Reply(conn net.Conn, rep byte, bindAddr string, bindPort int) error {
	ip := net.ParseIP(bindAddr)
	buf := make([]byte, 0, 22)
	if ip != nil && ip.To4() == nil {
		// An IPv6 listener: the reply carries the 16 byte address.
		buf = append(buf, socks5Version, rep, 0x00, socks5IPv6)
		buf = append(buf, ip.To16()...)
	} else {
		if ip == nil {
			ip = net.IPv4zero
		}
		buf = append(buf, socks5Version, rep, 0x00, socks5IPv4)
		buf = append(buf, ip.To4()...)
	}
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

// socks5Authenticate runs the username and password method (RFC 1929).
//
// The comparison is constant time: the password of the proxy is a secret
// even when it is a short one, and a proxy that leaks its password one
// byte at a time is a proxy with a weak password.
func socks5Authenticate(conn net.Conn, user, password string) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks5: authentication: %w", err)
	}
	if head[0] != 0x01 {
		return fmt.Errorf("socks5: unsupported authentication version %d", head[0])
	}
	name := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, name); err != nil {
		return fmt.Errorf("socks5: authentication: %w", err)
	}
	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return fmt.Errorf("socks5: authentication: %w", err)
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return fmt.Errorf("socks5: authentication: %w", err)
	}
	ok := subtle.ConstantTimeCompare(name, []byte(user)) == 1 &&
		subtle.ConstantTimeCompare(pass, []byte(password)) == 1
	reply := []byte{0x01, 0x00}
	if !ok {
		reply[1] = 0x01
	}
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("socks5: authentication reply: %w", err)
	}
	if !ok {
		return errors.New("socks5: the credentials were refused")
	}
	return nil
}
