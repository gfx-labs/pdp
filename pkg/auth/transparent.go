package auth

import (
	"context"
	"net"
	"net/http"
	"net/netip"
)

type transparentKey struct{}

// TransparentConnContext marks a connection accepted on a DNS-steered listener.
// Such a client believes it reached the destination, so it proves nothing about
// itself. The source address is the only fact, and it is only as trustworthy as
// the network's protection against spoofing.
func TransparentConnContext(ctx context.Context, c net.Conn) context.Context {
	var ip string
	if addr, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		ip = addr.Addr().Unmap().String()
	}
	return context.WithValue(ctx, transparentKey{}, ip)
}

func IsTransparent(ctx context.Context) bool {
	_, ok := ctx.Value(transparentKey{}).(string)
	return ok
}

type Transparent struct{}

func (Transparent) Authenticate(r *http.Request) (Identity, error) {
	ip, ok := r.Context().Value(transparentKey{}).(string)
	if !ok || ip == "" {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Method: "transparent", IP: ip}, nil
}
