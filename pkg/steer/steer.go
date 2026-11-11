// Package steer answers DNS so that configured names resolve to the gateway.
// It claims only names the administrator listed. Every other name is forwarded
// unchanged or refused.
package steer

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxPacketBytes = 4096
	answerTTL      = 30
	forwardTimeout = 5 * time.Second
	maxInFlight    = 256
)

type Config struct {
	// Address is the gateway address returned for intercepted names.
	Address netip.Addr
	// Names are exact lower-case hosts, or "*.suffix" for every name below a suffix.
	Names []string
	// ForwardTo is the resolver for names that are not intercepted, as
	// host:port. Empty refuses them.
	ForwardTo string
}

type Server struct {
	address  netip.Addr
	exact    map[string]bool
	suffixes []string
	forward  string
	slots    chan struct{}
}

func New(c Config) (*Server, error) {
	if !c.Address.IsValid() || c.Address.IsUnspecified() {
		return nil, errors.New("DNS steering needs the gateway address")
	}
	s := &Server{address: c.Address.Unmap(), exact: make(map[string]bool), forward: c.ForwardTo, slots: make(chan struct{}, maxInFlight)}
	for _, name := range c.Names {
		suffix, wildcard := strings.CutPrefix(name, "*.")
		if suffix == "" || suffix != strings.ToLower(suffix) || strings.ContainsAny(suffix, "*/ ") || strings.HasSuffix(suffix, ".") || strings.HasPrefix(suffix, ".") {
			return nil, errors.New("invalid DNS intercept name")
		}
		if wildcard {
			s.suffixes = append(s.suffixes, "."+suffix)
		} else {
			s.exact[suffix] = true
		}
	}
	if c.ForwardTo != "" {
		if _, err := netip.ParseAddrPort(c.ForwardTo); err != nil {
			return nil, errors.New("DNS forward resolver must be an address and port")
		}
	}
	return s, nil
}

// Intercepts reports whether a query for name is answered with the gateway.
func (s *Server) Intercepts(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if s.exact[name] {
		return true
	}
	for _, suffix := range s.suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// Serve answers queries until the connection is closed.
func (s *Server) Serve(conn net.PacketConn) error {
	for {
		buffer := make([]byte, maxPacketBytes)
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() { <-s.slots }()
				if reply := s.answer(buffer[:n]); reply != nil {
					_, _ = conn.WriteTo(reply, from)
				}
			}()
		default:
			// Dropped under load. The client retries.
		}
	}
}

func (s *Server) answer(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil || header.Response {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return nil
	}
	reply := dnsmessage.Header{ID: header.ID, Response: true, OpCode: header.OpCode, RecursionDesired: header.RecursionDesired, RecursionAvailable: true}
	if header.OpCode != 0 || question.Class != dnsmessage.ClassINET {
		reply.RCode = dnsmessage.RCodeNotImplemented
		return pack(reply, question, nil)
	}
	if !s.Intercepts(question.Name.String()) {
		if s.forward == "" {
			reply.RCode = dnsmessage.RCodeRefused
			return pack(reply, question, nil)
		}
		return s.relay(query, reply, question)
	}
	reply.Authoritative = true
	// Another record type gets an empty answer, so the client falls back to
	// the address family the gateway listens on.
	var body dnsmessage.ResourceBody
	switch {
	case question.Type == dnsmessage.TypeA && s.address.Is4():
		body = &dnsmessage.AResource{A: s.address.As4()}
	case question.Type == dnsmessage.TypeAAAA && s.address.Is6():
		body = &dnsmessage.AAAAResource{AAAA: s.address.As16()}
	}
	return pack(reply, question, body)
}

func pack(header dnsmessage.Header, question dnsmessage.Question, body dnsmessage.ResourceBody) []byte {
	message := dnsmessage.Message{Header: header, Questions: []dnsmessage.Question{question}}
	if body != nil {
		message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: question.Class, TTL: answerTTL}, Body: body}}
	}
	data, err := message.Pack()
	if err != nil {
		return nil
	}
	return data
}

// relay passes the client's packet to the real resolver and returns its answer
// unchanged, so every record type and DNSSEC bit survives.
func (s *Server) relay(query []byte, failure dnsmessage.Header, question dnsmessage.Question) []byte {
	failure.RCode = dnsmessage.RCodeServerFailure
	conn, err := net.DialTimeout("udp", s.forward, forwardTimeout)
	if err != nil {
		return pack(failure, question, nil)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(forwardTimeout))
	if _, err = conn.Write(query); err != nil {
		return pack(failure, question, nil)
	}
	reply := make([]byte, maxPacketBytes)
	n, err := conn.Read(reply)
	if err != nil || n < 12 || reply[0] != query[0] || reply[1] != query[1] {
		return pack(failure, question, nil)
	}
	return reply[:n]
}
