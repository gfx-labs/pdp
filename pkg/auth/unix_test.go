//go:build linux

package auth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUnixPeerBinding(t *testing.T) {
	socket := filepath.Join(privateSocketDir(t), "peer.sock")
	listener, err := ListenUnix(socket, 0600)
	if err != nil {
		t.Fatal(err)
	}
	authn := NewUnix()
	server := &http.Server{ConnContext: ConnContext, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, err := authn.Authenticate(r)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		fmt.Fprintf(w, "%s %s", identity.Method, identity.ID())
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	request, err := http.NewRequest("GET", "http://pdp/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Principal", "administrator")
	request.Header.Set("X-Uid", "0")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != fmt.Sprintf("unix uid:%d", os.Getuid()) {
		t.Fatalf("peer UID not kernel bound: %s", body)
	}
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %o", info.Mode().Perm())
	}
}

func TestInheritedUnix(t *testing.T) {
	if os.Getenv("PDP_TEST_ACTIVATED") == "1" {
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		listener, ok, err := InheritedUnixListener()
		if err != nil || !ok {
			t.Fatalf("socket activation: %v", err)
		}
		defer listener.Close()
		if os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_PID") != "" {
			t.Fatal("activation environment leaked to child")
		}
		connection, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		uid, err := peerUID(connection)
		if err != nil || uid != uint32(os.Getuid()) {
			t.Fatalf("inherited listener lost kernel credentials: %d %v", uid, err)
		}
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := http.ReadRequest(bufio.NewReader(connection))
		if err != nil {
			t.Fatal(err)
		}
		request.Body.Close()
		io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nactivated")
		return
	}
	socket := filepath.Join(privateSocketDir(t), "systemd.sock")
	listener, err := ListenUnix(socket, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestInheritedUnix$")
	command.Env = append(os.Environ(), "PDP_TEST_ACTIVATED=1", "LISTEN_FDS=1")
	command.ExtraFiles = []*os.File{file}
	var output strings.Builder
	command.Stdout = &output
	command.Stderr = &output
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		command.Process.Kill()
		command.Wait()
		t.Fatalf("activation connection: %v output=%s", err, output.String())
	}
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(connection, "GET / HTTP/1.1\r\nHost: pdp\r\n\r\n")
	response, readErr := http.ReadResponse(bufio.NewReader(connection), nil)
	if readErr == nil {
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(data) != "activated" {
			t.Errorf("activation body: %s", data)
		}
	}
	connection.Close()
	if readErr != nil {
		command.Process.Kill()
	}
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil {
		t.Fatalf("child: read=%v exit=%v output=%s", readErr, waitErr, output.String())
	}
	if _, err = os.Stat(socket); err != nil {
		t.Fatal("child removed systemd-owned socket path")
	}
}

func TestUnixPathOwnership(t *testing.T) {
	path := filepath.Join(privateSocketDir(t), "existing")
	if err := os.WriteFile(path, []byte("must remain"), 0600); err != nil {
		t.Fatal(err)
	}
	if listener, err := ListenUnix(path, 0600); err == nil {
		listener.Close()
		t.Fatal("existing path replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "must remain" {
		t.Fatal("existing path changed")
	}
	if listener, err := ListenUnix(path+"-world", 0666); err == nil {
		listener.Close()
		t.Fatal("world-accessible socket allowed")
	}
	dir := filepath.Dir(path)
	unsafe := filepath.Join(dir, "untrusted")
	if err = os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path, filepath.Join(unsafe, "p.sock")); err != nil {
		t.Fatal(err)
	}
	if listener, err := ListenUnix(filepath.Join(unsafe, "p.sock"), 0660); err == nil {
		listener.Close()
		t.Fatal("untrusted parent accepted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("socket setup changed a symlink target's permissions")
	}
	link := filepath.Join(dir, "parent-link")
	if err = os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if listener, err := ListenUnix(filepath.Join(link, "new.sock"), 0600); err == nil {
		listener.Close()
		t.Fatal("symlink parent accepted")
	}
}

func privateSocketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
