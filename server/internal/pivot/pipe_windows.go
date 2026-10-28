//go:build windows

package pivot

// A named pipe is the Windows equivalent of a Unix socket: it lives in
// the file system of the host, and only a process on the host can open
// it.  A pivot that listens on one is therefore reachable by the tools of
// the host and by nothing else.
//
// The standard library of Go has no named pipe of its own, so the calls of
// the operating system are made through the dynamic loader.  Everything
// above the listener stays the same: it is a net.Listener, and the proxy
// does not know what it listens on.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The flags of CreateNamedPipe and the errors of the pipe that mean
// something to the caller.
const (
	pipeAccessDuplex   = 0x00000003
	pipeTypeByte       = 0x00000000
	pipeReadModeByte   = 0x00000000
	pipeWait           = 0x00000000
	pipeUnlimited      = 255
	pipeBufferSize     = 64 * 1024
	errorPipeConnected = 535
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procCreateNamedPipe     = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = kernel32.NewProc("DisconnectNamedPipe")
)

// pipeListener serves the clients of a named pipe.
type pipeListener struct {
	name   string
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

// newPipeListener opens a named pipe and serves the clients that connect
// to it.
//
// The name is the full path of the pipe ("\\.\pipe\umbra-1").  A short
// name is put in front of the usual prefix.
func newPipeListener(name string) (net.Listener, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return nil, errors.New("pivot: the named pipe needs a name")
	}
	if !strings.HasPrefix(clean, `\\`) {
		clean = `\\.\pipe\` + strings.TrimPrefix(clean, `\\.\pipe\`)
	}
	l := &pipeListener{
		name:   clean,
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
	go l.serve()
	return l, nil
}

// serve waits for the clients of the pipe.
//
// One instance of the pipe serves one client at a time.  The next
// instance is created before the current one is handed over, so a second
// client never has to wait for the first one to leave.
func (l *pipeListener) serve() {
	for {
		handle, err := createPipe(l.name)
		if err != nil {
			select {
			case <-l.closed:
			default:
				l.once.Do(func() { close(l.conns) })
			}
			return
		}
		if err := connectPipe(handle); err != nil {
			_ = syscall.CloseHandle(handle)
			continue
		}
		conn := &pipeConn{handle: handle}
		select {
		case l.conns <- conn:
		case <-l.closed:
			_ = conn.Close()
			return
		}
	}
}

// Accept waits for the next client of the pipe.
func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close stops the listener.
func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr is the name of the pipe.
func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.name) }

// pipeAddr is the address of a named pipe.
type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }

func (a pipeAddr) String() string { return string(a) }

// pipeConn is one client of the pipe.
type pipeConn struct {
	handle syscall.Handle
	mu     sync.Mutex
	closed bool
}

func (c *pipeConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	var n uint32
	if err := syscall.ReadFile(c.handle, b, &n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (c *pipeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	var n uint32
	if err := syscall.WriteFile(c.handle, b, &n); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	_, _, _ = procDisconnectNamedPipe.Call(uintptr(c.handle), 0)
	return syscall.CloseHandle(c.handle)
}

func (c *pipeConn) LocalAddr() net.Addr  { return pipeAddr("") }
func (c *pipeConn) RemoteAddr() net.Addr { return pipeAddr("") }

func (c *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

// createPipe creates one instance of the named pipe.
func createPipe(name string) (syscall.Handle, error) {
	wide, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	handle, _, callErr := procCreateNamedPipe.Call(
		uintptr(unsafe.Pointer(wide)),
		uintptr(pipeAccessDuplex),
		uintptr(pipeTypeByte|pipeReadModeByte|pipeWait),
		uintptr(pipeUnlimited),
		uintptr(pipeBufferSize),
		uintptr(pipeBufferSize),
		uintptr(0),
		uintptr(0),
	)
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		return 0, fmt.Errorf("pivot: the named pipe %s could not be created: %v", name, callErr)
	}
	return syscall.Handle(handle), nil
}

// connectPipe waits for a client of the pipe.
func connectPipe(handle syscall.Handle) error {
	_, _, callErr := procConnectNamedPipe.Call(uintptr(handle), 0, 0, 0, 0)
	if callErr == nil || callErr == syscall.Errno(0) {
		return nil
	}
	// The client was faster than the server: the pipe is connected
	// already and the call says so.
	if errno, ok := callErr.(syscall.Errno); ok && errno == errorPipeConnected {
		return nil
	}
	return callErr
}
