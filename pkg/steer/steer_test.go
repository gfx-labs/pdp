package steer

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func serve(t *testing.T, c Config) string {
	t.Helper()
	server, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go server.Serve(conn)
	return conn.LocalAddr().String()
}

func query(t *testing.T, server, name string, kind dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET}}}
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var reply dnsmessage.Message
	if err = reply.Unpack(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	return reply
}

func addresses(m dnsmessage.Message) []string {
	var out []string
	for _, answer := range m.Answers {
		if a, ok := answer.Body.(*dnsmessage.AResource); ok {
			out = append(out, netip.AddrFrom4(a.A).String())
		}
	}
	return out
}

// Only configured names are steered to the gateway. Every other name keeps the
// real resolver's answer, or is refused when no resolver is configured.
func TestSteersOnlyConfiguredNames(t *testing.T) {
	// The real resolver is another instance that knows one name.
	real := serve(t, Config{Address: netip.MustParseAddr("192.0.2.53"), Names: []string{"elsewhere.test"}})
	gateway := netip.MustParseAddr("10.16.0.1")
	names := []string{"api.example.test", "*.cdn.example.test"}
	forwarding := serve(t, Config{Address: gateway, Names: names, ForwardTo: real})
	refusing := serve(t, Config{Address: gateway, Names: names})

	for _, name := range []string{"api.example.test.", "API.Example.Test.", "a.b.cdn.example.test."} {
		if got := addresses(query(t, forwarding, name, dnsmessage.TypeA)); len(got) != 1 || got[0] != "10.16.0.1" {
			t.Fatalf("%s was not steered to the gateway: %v", name, got)
		}
	}
	// An IPv4 gateway has no AAAA answer, so the client falls back to A.
	if reply := query(t, forwarding, "api.example.test.", dnsmessage.TypeAAAA); reply.RCode != dnsmessage.RCodeSuccess || len(reply.Answers) != 0 {
		t.Fatalf("AAAA for a steered name: %+v", reply)
	}
	for _, name := range []string{"elsewhere.test.", "cdn.example.test.", "api.example.test.evil.test."} {
		reply := query(t, refusing, name, dnsmessage.TypeA)
		if reply.RCode != dnsmessage.RCodeRefused || len(reply.Answers) != 0 {
			t.Fatalf("%s was answered with no resolver configured: %+v", name, reply)
		}
	}
	if got := addresses(query(t, forwarding, "elsewhere.test.", dnsmessage.TypeA)); len(got) != 1 || got[0] != "192.0.2.53" {
		t.Fatalf("unlisted name did not get the real resolver's answer: %v", got)
	}
}
