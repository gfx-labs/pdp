package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

var errRequest = errors.New("invalid request")

// destination is where a request will be sent. It never comes from the address
// a client connected to, only from the request line, Host, SNI or CONNECT target.
type destination struct {
	scheme string
	host   string
	port   int
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

func (d destination) key() string { return net.JoinHostPort(d.host, strconv.Itoa(d.port)) }

// authority is the Host value the destination expects.
func (d destination) authority() string {
	if d.port == defaultPort(d.scheme) {
		if strings.Contains(d.host, ":") {
			return "[" + d.host + "]"
		}
		return d.host
	}
	return d.key()
}

// normalizeHost lower-cases a host and removes a trailing dot, so one policy
// pattern cannot be bypassed by another spelling of the same name.
func normalizeHost(host string) (string, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", false
		}
		return addr.Unmap().String(), true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return host, true
}

func splitDestination(scheme, hostport string) (destination, bool) {
	host, rawPort := hostport, ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, rawPort = h, p
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	host, ok := normalizeHost(host)
	if !ok {
		return destination{}, false
	}
	port := defaultPort(scheme)
	if rawPort != "" {
		n, err := strconv.Atoi(rawPort)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != rawPort {
			return destination{}, false
		}
		port = n
	} else if scheme == "tcp" {
		return destination{}, false
	}
	return destination{scheme: scheme, host: host, port: port}, true
}

// requestDestination reads the destination of a non-CONNECT request: the
// absolute URL of a proxy request, or Host on a transparent listener.
func requestDestination(r *http.Request) (destination, bool) {
	if r.URL == nil || r.URL.User != nil || r.URL.Opaque != "" {
		return destination{}, false
	}
	if r.URL.IsAbs() {
		if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
			return destination{}, false
		}
		return splitDestination(r.URL.Scheme, r.URL.Host)
	}
	if !auth.IsTransparent(r.Context()) {
		return destination{}, false
	}
	if r.TLS == nil {
		return splitDestination("http", r.Host)
	}
	// The certificate was minted for the SNI name, so Host must agree with it.
	d, ok := splitDestination("https", r.Host)
	sni, sniOK := normalizeHost(r.TLS.ServerName)
	if !ok || !sniOK || sni != d.host {
		return destination{}, false
	}
	return d, true
}

func isWebSocket(r *http.Request) bool {
	return headerHasToken(r.Header, "Connection", "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// validateGeneric bounds a request to a destination with no pinned schema.
// Policy sees the escaped path, so dot segments in either form are refused.
func validateGeneric(r *http.Request, o Options) error {
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.RequestURI == "*" || r.URL.Fragment != "" || len(r.Header) > 128 || len(r.Trailer) != 0 {
		return errRequest
	}
	if r.Method == "" || r.Method == http.MethodConnect || r.Method != strings.ToUpper(r.Method) {
		return errRequest
	}
	path := r.URL.Path
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "\\") || !utf8.ValidString(path) {
		return errRequest
	}
	for _, form := range []string{path, r.URL.EscapedPath()} {
		for _, part := range strings.Split(form, "/") {
			if part == "." || part == ".." {
				return errRequest
			}
		}
	}
	headerBytes := len(r.Host) + len(r.URL.RequestURI())
	for name, values := range r.Header {
		headerBytes += len(name) + 4
		for _, v := range values {
			headerBytes += len(v) + 2
			if strings.ContainsAny(v, "\x00\r\n") {
				return errRequest
			}
		}
	}
	if headerBytes > o.MaxHeaderBytes {
		return errRequest
	}
	if r.Header.Get("Upgrade") != "" && !isWebSocket(r) {
		return errRequest
	}
	return nil
}

// validateStrict applies to schema-backed upstreams, where every ambiguity in
// path, query, encoding or framing is refused instead of forwarded.
func validateStrict(r *http.Request, o Options) error {
	if r.URL.Fragment != "" || r.URL.ForceQuery || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.RequestURI == "*" {
		return errRequest
	}
	switch r.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
	default:
		return errRequest
	}
	if len(r.URL.RequestURI()) > o.MaxHeaderBytes || len(r.Header) > 128 || len(r.TransferEncoding) != 0 || r.ContentLength < 0 || r.ContentLength > o.MaxRequestBytes || len(r.Trailer) != 0 {
		return errRequest
	}
	if !validPath(r.URL.Path) || r.URL.RawPath != "" || strings.Contains(r.URL.EscapedPath(), "%") {
		return errRequest
	}
	headerBytes := len(r.Host)
	for name, values := range r.Header {
		headerBytes += len(name) + 4
		for _, v := range values {
			headerBytes += len(v) + 2
			if strings.ContainsAny(v, "\x00\r\n") {
				return errRequest
			}
		}
	}
	if headerBytes > o.MaxHeaderBytes {
		return errRequest
	}
	for _, h := range []string{"Content-Type", "Content-Length", "Content-Encoding", "Accept-Encoding"} {
		if len(r.Header.Values(h)) > 1 {
			return errRequest
		}
	}
	for _, h := range []string{"Upgrade", "Trailer", "TE", "Transfer-Encoding", "Expect", "Content-Encoding"} {
		if r.Header.Get(h) != "" {
			return errRequest
		}
	}
	if headerHasToken(r.Header, "Connection", "upgrade") {
		return errRequest
	}
	if r.ContentLength > 0 && (r.Method == "GET" || r.Method == "HEAD") {
		return errRequest
	}
	if v := r.Header.Get("Content-Type"); v != "" {
		media, params, err := mime.ParseMediaType(v)
		if err != nil || media != "application/json" || len(params) > 1 {
			return errRequest
		}
		for k, v := range params {
			if k != "charset" || !strings.EqualFold(v, "utf-8") {
				return errRequest
			}
		}
	} else if r.ContentLength > 0 {
		return errRequest
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) > 128 {
		return errRequest
	}
	if r.URL.RawQuery != "" {
		for _, part := range strings.Split(r.URL.RawQuery, "&") {
			if part == "" || !strings.Contains(part, "=") {
				return errRequest
			}
		}
	}
	for k, values := range q {
		if k == "" || len(values) != 1 || !utf8.ValidString(k) || strings.ContainsAny(k, "\x00\r\n\\%") {
			return errRequest
		}
		if !utf8.ValidString(values[0]) || strings.ContainsAny(values[0], "\x00\r\n\\%") {
			return errRequest
		}
	}
	return nil
}

func validPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || strings.ContainsAny(path, "\\%?#") || !utf8.ValidString(path) {
		return false
	}
	for _, c := range path {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// normalize validates a request against the upstream's pinned schema and
// returns the canonical body and query that will be forwarded.
func normalize(r *http.Request, up *upstream, max int64) (*schema.Request, []byte, url.Values, error) {
	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, max+1))
		if err != nil || int64(len(body)) > max {
			return nil, nil, nil, errRequest
		}
	}
	if int64(len(body)) != r.ContentLength {
		return nil, nil, nil, errRequest
	}
	if len(body) > 0 && !utf8.Valid(body) {
		return nil, nil, nil, errRequest
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, nil, nil, errRequest
	}
	var n *schema.Request
	if up.REST != nil {
		copy := r.Clone(r.Context())
		copy.URL = &url.URL{Path: r.URL.Path, RawQuery: query.Encode()}
		copy.RequestURI = copy.URL.RequestURI()
		copy.Body = io.NopCloser(bytes.NewReader(body))
		n, err = up.REST.Normalize(copy)
		if err != nil {
			return nil, nil, nil, errRequest
		}
		if len(body) > 0 {
			body, err = json.Marshal(n.Body)
			if err != nil {
				return nil, nil, nil, errRequest
			}
		}
	} else {
		if r.Method != "POST" || len(query) != 0 || len(body) == 0 {
			return nil, nil, nil, errRequest
		}
		envelope, decodeErr := schema.DecodeJSON(body)
		object, ok := envelope.(map[string]any)
		if decodeErr != nil || !ok {
			return nil, nil, nil, errRequest
		}
		for k := range object {
			if k != "query" && k != "operationName" && k != "variables" {
				return nil, nil, nil, errRequest
			}
		}
		document, ok := object["query"].(string)
		if !ok || len(document) == 0 {
			return nil, nil, nil, errRequest
		}
		operationName := ""
		if raw, ok := object["operationName"]; ok {
			operationName, ok = raw.(string)
			if !ok {
				return nil, nil, nil, errRequest
			}
		}
		variables := map[string]any{}
		if raw, ok := object["variables"]; ok && raw != nil {
			variables, ok = raw.(map[string]any)
			if !ok {
				return nil, nil, nil, errRequest
			}
		}
		n, err = up.GraphQL.Normalize(document, operationName, variables)
		if err != nil || n.OperationType == "subscription" {
			return nil, nil, nil, errRequest
		}
		n.Method = r.Method
		forwarded := map[string]any{"query": document, "variables": n.Variables}
		if operationName != "" {
			forwarded["operationName"] = operationName
		}
		body, err = json.Marshal(forwarded)
		if err != nil {
			return nil, nil, nil, errRequest
		}
	}
	if int64(len(body)) > max {
		return nil, nil, nil, errRequest
	}
	return n, body, query, nil
}

func policyIdentity(identity auth.Identity) policy.Identity {
	out := policy.Identity{ID: identity.ID(), AuthMethod: identity.Method, SPIFFEID: identity.SPIFFEID, IP: identity.IP}
	if identity.Method == "unix" {
		uid := identity.UID
		out.UID = &uid
	}
	return out
}

// addSchemaFacts adds what the pinned schema established about the request.
func addSchemaFacts(input *policy.Input, up *upstream, n *schema.Request, path string, query url.Values) {
	input.Plugin, input.SchemaDigest = up.Plugin, up.digest
	input.HTTP = &policy.HTTPInput{Method: n.Method, Path: path, PathParams: map[string]string{}, Query: query, NormalizedQuery: n.Query, Body: n.Body}
	input.OperationType, input.OperationName, input.Variables = n.OperationType, n.OperationName, n.Variables
	for k, v := range n.Path {
		input.HTTP.PathParams[k] = fmt.Sprint(v)
	}
	if len(n.Fields) == 0 {
		input.Operations = []policy.OperationInput{{ID: n.OperationID}}
	}
	for _, f := range n.Fields {
		input.Operations = append(input.Operations, policy.OperationInput{ID: f.Coordinate})
		input.GraphQL = append(input.GraphQL, policy.FieldOccurrence{Coordinate: f.Coordinate, Path: f.Path, Arguments: f.Arguments})
	}
}

// carriesPlaceholder reports whether a request names this binding's placeholder
// in a header value or, for a token request, in its body.
func carriesPlaceholder(h http.Header, body []byte, placeholder string) bool {
	if len(body) > 0 && bytes.Contains(body, []byte(placeholder)) {
		return true
	}
	for _, values := range h {
		for _, v := range values {
			if v == placeholder || strings.HasSuffix(v, " "+placeholder) {
				return true
			}
			if scheme, encoded, ok := strings.Cut(v, " "); ok && strings.EqualFold(scheme, "Basic") {
				if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
					for _, part := range strings.SplitN(string(decoded), ":", 2) {
						if part == placeholder {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// Hop-by-hop headers end at this proxy in both directions (RFC 9110 7.6.1).
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Expect"}

func removeHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "{\"error\":\""+code+"\"}\n")
}
