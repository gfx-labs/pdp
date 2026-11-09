package auth

import (
	"errors"
	"net"
	"os"
	"strconv"
)

// InheritedUnixListener accepts exactly one systemd-owned Unix stream socket.
// LISTEN_PID prevents accidental adoption of a parent's descriptors.
func InheritedUnixListener() (net.Listener, bool, error) {
	pidText, nText := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	if pidText == "" && nText == "" {
		return nil, false, nil
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid != os.Getpid() {
		return nil, false, errors.New("invalid socket activation process")
	}
	n, err := strconv.Atoi(nText)
	if err != nil || n != 1 {
		return nil, false, errors.New("exactly one inherited socket is required")
	}
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	f := os.NewFile(3, "systemd-listener")
	if f == nil {
		return nil, false, errors.New("invalid inherited descriptor")
	}
	defer f.Close()
	l, err := net.FileListener(f)
	if err != nil {
		return nil, false, errors.New("cannot adopt inherited socket")
	}
	if _, ok := l.(*net.UnixListener); !ok {
		l.Close()
		return nil, false, errors.New("inherited socket must be Unix stream")
	}
	// systemd owns the socket path and remains responsible for its lifecycle.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	return l, true, nil
}
