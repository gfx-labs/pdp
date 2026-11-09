//go:build linux

package auth

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func peerUID(c net.Conn) (uint32, error) {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a Unix connection")
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	if cred == nil {
		return 0, ErrUnauthenticated
	}
	return cred.Uid, nil
}

func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if !trustedSocketParent(path) {
		return nil, errors.New("Unix socket requires a trusted parent directory")
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot create Unix socket")
	}
	f := os.NewFile(uintptr(fd), "pdp-unix-listener")
	defer f.Close()
	if err = syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		return nil, errors.New("cannot bind Unix socket")
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(path)
		}
	}()
	// Set filesystem permissions before any process can connect to the socket.
	if err = os.Chmod(path, mode); err != nil {
		return nil, errors.New("cannot set Unix socket permissions")
	}
	if err = syscall.Listen(fd, 128); err != nil {
		return nil, errors.New("cannot listen on Unix socket")
	}
	l, err := net.FileListener(f)
	if err != nil {
		return nil, errors.New("cannot adopt Unix listener")
	}
	l.(*net.UnixListener).SetUnlinkOnClose(true)
	cleanup = false
	return l, nil
}

func trustedSocketParent(path string) bool {
	if filepath.Clean(path) != path {
		return false
	}
	parent := filepath.Dir(path)
	parts := strings.Split(strings.TrimPrefix(parent, "/"), "/")
	current := "/"
	privateAncestor := false
	for i, part := range parts {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return false
		}
		if info.Mode().Perm()&0022 != 0 && (!privateAncestor || i == len(parts)-1) {
			// A sticky ancestor such as /tmp protects the next daemon-owned child.
			if i == len(parts)-1 || info.Mode()&os.ModeSticky == 0 {
				return false
			}
		}
		if info.Mode().Perm()&0077 == 0 {
			privateAncestor = true
		}
	}
	return true
}
