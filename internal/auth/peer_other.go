//go:build !linux

package auth

import (
	"errors"
	"net"
	"os"
)

func peerUID(net.Conn) (uint32, error) { return 0, ErrUnauthenticated }

func listenUnix(string, os.FileMode) (net.Listener, error) {
	return nil, errors.New("Unix peer authentication requires Linux")
}
