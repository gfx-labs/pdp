package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gfx-labs/pdp/internal/auth"
	"github.com/gfx-labs/pdp/internal/policy"
	"github.com/gfx-labs/pdp/internal/schema"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

var errRequest = errors.New("invalid request")

func selectRoute(path string) (string, string, bool) {
	if strings.HasPrefix(path, "/upstreams/github/") {
		return "github", strings.TrimPrefix(path, "/upstreams/github"), true
	}
	if path == "/upstreams/linear/graphql" {
		return "linear", "/graphql", true
	}
	return "", "", false
}

func validateRequest(r *http.Request, o Options) error {
	if r.URL == nil || r.URL.IsAbs() || r.URL.Host != "" || r.URL.User != nil || r.URL.Opaque != "" || r.URL.Fragment != "" || r.URL.ForceQuery || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.RequestURI == "*" {
		return errRequest
	}
	if r.RequestURI != "" && (!strings.HasPrefix(r.RequestURI, "/") || strings.HasPrefix(r.RequestURI, "//")) {
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
	for _, v := range r.Header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return errRequest
			}
		}
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

func normalize(r *http.Request, path string, route route, max int64) (*schema.Request, []byte, url.Values, error) {
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
	copy := r.Clone(r.Context())
	copy.URL.Path = path
	copy.URL.RawPath = ""
	copy.URL.RawQuery = query.Encode()
	copy.RequestURI = copy.URL.RequestURI()
	copy.Body = io.NopCloser(bytes.NewReader(body))
	var n *schema.Request
	if route.Provider == "github" {
		if route.REST != nil {
			n, err = route.REST.Normalize(copy)
			if err != nil {
				return nil, nil, nil, errRequest
			}
		} else {
			n = &schema.Request{Protocol: "rest", OperationID: "untyped:http:" + r.Method, Method: r.Method}
			if len(body) > 0 {
				n.Body, err = schema.DecodeJSON(body)
				if err != nil {
					return nil, nil, nil, errRequest
				}
				if _, ok := n.Body.(map[string]any); !ok {
					return nil, nil, nil, errRequest
				}
			}
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
		if route.GraphQL != nil {
			n, err = route.GraphQL.Normalize(document, operationName, variables)
		} else {
			n, err = normalizeUntypedGraphQL(document, operationName, variables)
		}
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

func normalizeUntypedGraphQL(document, operationName string, variables map[string]any) (*schema.Request, error) {
	parsed, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: document}, schema.MaxQueryTokens)
	if err != nil || len(parsed.Operations) != 1 || len(parsed.Fragments) != 0 {
		return nil, errRequest
	}
	operation := parsed.Operations[0]
	if operation.Operation == ast.Subscription || len(operation.Directives) != 0 || (operationName != "" && operation.Name != operationName) {
		return nil, errRequest
	}
	fields := 0
	var walk func(ast.SelectionSet, int) error
	walk = func(set ast.SelectionSet, depth int) error {
		if depth > 32 {
			return errRequest
		}
		for _, sel := range set {
			field, ok := sel.(*ast.Field)
			if !ok || len(field.Directives) != 0 || strings.HasPrefix(field.Name, "__") {
				return errRequest
			}
			fields++
			if fields > 256 {
				return errRequest
			}
			if err := walk(field.SelectionSet, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(operation.SelectionSet, 0); err != nil {
		return nil, err
	}
	return &schema.Request{Protocol: "graphql", OperationID: "untyped:graphql:" + string(operation.Operation), OperationType: string(operation.Operation), OperationName: operation.Name, Variables: variables}, nil
}

func policyInput(identity auth.Identity, route route, n *schema.Request, path string, query url.Values) policy.Input {
	input := policy.Input{Version: policy.InputVersion, Identity: policy.Identity{ID: identity.Principal, AuthMethod: identity.Method, SPIFFEID: identity.SPIFFEID}, Provider: route.Provider, Binding: route.Binding,
		HTTP:          policy.HTTPInput{Method: n.Method, Path: path, PathParams: map[string]string{}, Query: query, NormalizedQuery: n.Query, Body: n.Body},
		OperationType: n.OperationType, OperationName: n.OperationName, Variables: n.Variables}
	if identity.Method == "unix" {
		uid := identity.UID
		input.Identity.UID = &uid
	}
	for k, v := range n.Path {
		input.HTTP.PathParams[k] = fmt.Sprint(v)
	}
	if route.REST != nil {
		input.SchemaDigest = route.REST.Digest()
	}
	if route.GraphQL != nil {
		input.SchemaDigest = route.GraphQL.Digest()
	}
	if len(n.Fields) == 0 {
		input.Operations = []policy.OperationInput{{ID: n.OperationID}}
	}
	for _, f := range n.Fields {
		input.Operations = append(input.Operations, policy.OperationInput{ID: f.Coordinate})
		input.GraphQL = append(input.GraphQL, policy.FieldOccurrence{Coordinate: f.Coordinate, Path: f.Path, Arguments: f.Arguments})
	}
	return input
}

func newUpstreamRequest(ctx context.Context, in *http.Request, target *url.URL, body []byte, provider string) (*http.Request, error) {
	out, err := http.NewRequestWithContext(ctx, in.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	// Constructing a fresh header set strips all caller auth, cookies and hop headers,
	// including arbitrary custom authentication header names configured by adapters.
	out.Header.Set("Accept", "application/json")
	out.Header.Set("Accept-Encoding", "identity")
	out.Header.Set("User-Agent", "pdp/1")
	if len(body) > 0 {
		out.Header.Set("Content-Type", "application/json")
	}
	if provider == "github" {
		out.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	out.Close = true
	out.GetBody = nil
	return out, nil
}

func readResponse(r *http.Response, o Options) ([]byte, error) {
	if r.StatusCode < 200 || r.StatusCode >= 300 && r.StatusCode < 400 || r.StatusCode == 101 || len(r.Trailer) != 0 || r.Header.Get("Trailer") != "" || r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" {
		return nil, errRequest
	}
	if len(r.Header.Values("Content-Type")) > 1 {
		return nil, errRequest
	}
	if typ := r.Header.Get("Content-Type"); typ != "" {
		media, params, err := mime.ParseMediaType(typ)
		if err != nil || media != "application/json" || len(params) > 1 {
			return nil, errRequest
		}
		for k, v := range params {
			if k != "charset" || !strings.EqualFold(v, "utf-8") {
				return nil, errRequest
			}
		}
	}
	if r.ContentLength > o.MaxResponseBytes {
		return nil, errRequest
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, o.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > o.MaxResponseBytes || len(r.Trailer) != 0 {
		return nil, errRequest
	}
	if r.StatusCode < 400 && len(data) > 0 {
		if _, err := schema.DecodeJSON(data); err != nil {
			return nil, errRequest
		}
	}
	return data, nil
}

func copyResponseHeaders(dst, src http.Header) {
	if src.Get("Content-Type") != "" {
		dst.Set("Content-Type", "application/json")
	}
	// Cookies, Location, auth challenges, Link, debug and server headers are omitted.
	for _, name := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"} {
		value := src.Get(name)
		if value != "" {
			if n, err := strconv.ParseUint(value, 10, 64); err == nil {
				dst.Set(name, strconv.FormatUint(n, 10))
			}
		}
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "{\"error\":\""+code+"\"}\n")
}
