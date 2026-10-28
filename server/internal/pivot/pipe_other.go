//go:build !windows

package pivot

import (
	"errors"
	"net"
)

// newPipeListener opens a named pipe.
//
// A named pipe is a Windows thing: on the other systems the pivot
// listens on a TCP socket, and the operator is told so instead of
// waiting for a listener that will never come.
func newPipeListener(name string) (net.Listener, error) {
	return nil, errors.New("pivot: a named pipe is only available on Windows")
}
