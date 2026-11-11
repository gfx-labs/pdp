// Package credential runs administrator-owned credential adapters. It is not a
// policy evaluator and must only be called after request authorization.
package credential

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Kind describes the upstream authentication scheme.
type Kind string

const (
	Bearer Kind = "bearer"
	Basic  Kind = "basic"
	Header Kind = "header"
)

// Result deliberately keeps credential material out of formatting and JSON.
// Apply is the only secret-bearing export and must target an authorized upstream.
type Result struct {
	Kind      Kind      `json:"kind"`
	ExpiresAt time.Time `json:"expires_at"`
	token     string
	username  string
	header    string
}

func (r Result) String() string                { return "credential.Result([redacted])" }
func (r Result) GoString() string              { return r.String() }
func (r Result) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte(r.String())) }
func (r Result) Apply(h http.Header) error {
	if h == nil || r.token == "" || !time.Now().Before(r.ExpiresAt) {
		return failure(CodeUnavailable)
	}
	switch r.Kind {
	case Bearer:
		h.Set("Authorization", "Bearer "+r.token)
	case Basic:
		req := &http.Request{Header: h}
		req.SetBasicAuth(r.username, r.token)
	case Header:
		h.Set(r.header, r.token)
	default:
		return failure(CodeInvalid)
	}
	return nil
}

// ContainsSecret detects reflected credential material in a bounded upstream
// response without exposing it to the gateway or policy. Call before forwarding
// response bodies or header values. JSON token iteration retains duplicate keys.
func (r Result) ContainsSecret(data []byte) bool {
	if r.token == "" {
		return false
	}
	patterns := []string{r.token}
	switch r.Kind {
	case Bearer:
		patterns = append(patterns, "Bearer "+r.token)
	case Basic:
		encoded := base64.StdEncoding.EncodeToString([]byte(r.username + ":" + r.token))
		patterns = append(patterns, encoded, "Basic "+encoded)
	}
	contains := func(value []byte) bool {
		for _, pattern := range patterns {
			if bytes.Contains(value, []byte(pattern)) {
				return true
			}
		}
		return false
	}
	if contains(data) {
		return true
	}
	for _, pattern := range patterns {
		encoded, _ := json.Marshal(pattern)
		if len(encoded) > 2 && bytes.Contains(data, encoded[1:len(encoded)-1]) {
			return true
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		value, err := decoder.Token()
		if err != nil {
			return false
		}
		if text, ok := value.(string); ok && contains([]byte(text)) {
			return true
		}
	}
}

// Request contains only identifiers and authorized scopes, never credentials.
type Request struct {
	Provider string   `json:"provider"`
	Binding  string   `json:"binding"`
	Scopes   []string `json:"scopes"`
}

// Stats is a coherent cumulative snapshot without credential or provider labels.
// Misses includes coalesced and saturated requests. Acquisitions and Failures
// count actual executions, not joining callers or rejected requests.
type Stats struct {
	Hits                   uint64 `json:"hits"`
	Misses                 uint64 `json:"misses"`
	Coalesced              uint64 `json:"coalesced"`
	Acquisitions           uint64 `json:"acquisitions"`
	Failures               uint64 `json:"failures"`
	InFlight               uint64 `json:"in_flight"`
	AcquisitionNanoseconds uint64 `json:"acquisition_nanoseconds"`
}

// SecretSource selects a mounted file or a name in the systemd credentials dir.
// Exactly one selector is required. Values are read only inside native helpers.
type SecretSource struct {
	File              string `json:"file,omitempty"`
	SystemdCredential string `json:"systemd_credential,omitempty"`
}

// ProviderConfig and scripts are administrator configuration, not user policy.
// Endpoints are exact HTTPS URLs. Scripts cannot choose hosts, paths or redirects.
type ProviderConfig struct {
	Script     string            `json:"script,omitempty"`
	ScriptFile string            `json:"script_file,omitempty"`
	Endpoints  map[string]string `json:"endpoints,omitempty"`
}

type GitHubConfig struct {
	AppID         string            `json:"app_id"`
	RepositoryIDs []int64           `json:"repository_ids"`
	Permissions   map[string]string `json:"permissions"`
}

type BindingConfig struct {
	Provider   string                  `json:"provider"`
	Secrets    map[string]SecretSource `json:"secrets,omitempty"`
	Parameters map[string]string       `json:"parameters,omitempty"`
	Scopes     []string                `json:"scopes,omitempty"`
	// StateFile contains the complete rotating OAuth token pair. Its parent must
	// be private and writable. Every writer must use the adjacent .lock file.
	StateFile string        `json:"state_file,omitempty"`
	GitHub    *GitHubConfig `json:"github,omitempty"`
	// LinearActor is mandatory for Linear adapters: app for client credentials,
	// app or user for a pre-authorized refresh-token installation.
	LinearActor string `json:"linear_actor,omitempty"`
}

type Limits struct {
	MaxSteps             uint64        `json:"max_steps,omitempty"`
	Timeout              time.Duration `json:"timeout,omitempty"`
	MaxConcurrent        int           `json:"max_concurrent,omitempty"`
	MaxInputBytes        int           `json:"max_input_bytes,omitempty"`
	MaxOutputBytes       int           `json:"max_output_bytes,omitempty"`
	MaxScriptBytes       int           `json:"max_script_bytes,omitempty"`
	MaxHTTPResponseBytes int           `json:"max_http_response_bytes,omitempty"`
	CacheEntries         int           `json:"cache_entries,omitempty"`
	ExpiryMargin         time.Duration `json:"expiry_margin,omitempty"`
}

type Config struct {
	Providers            map[string]ProviderConfig `json:"providers"`
	Bindings             map[string]BindingConfig  `json:"bindings"`
	Limits               Limits                    `json:"limits,omitempty"`
	CredentialsDirectory string                    `json:"credentials_directory,omitempty"`
	// RootCAs augments explicit trust for private provider HTTPS endpoints.
	// TLS certificate verification is never disabled.
	RootCAs *x509.CertPool `json:"-"`
}

type Code string

const (
	CodeInvalid     Code = "invalid_configuration_or_request"
	CodeUnavailable Code = "credential_unavailable"
	CodeLimited     Code = "credential_limit_exceeded"
	CodeCanceled    Code = "credential_canceled"
	CodePersistence Code = "credential_persistence_failed"
)

// Error intentionally has no provider body, URL, script traceback or cause.
type Error struct{ Code Code }

func (e *Error) Error() string { return string(e.Code) }
func failure(c Code) error     { return &Error{Code: c} }

func validValue(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validHeader(s string) bool {
	if s == "" || strings.EqualFold(s, "Host") || strings.EqualFold(s, "Content-Length") || strings.EqualFold(s, "Connection") || strings.EqualFold(s, "Proxy-Authorization") || strings.EqualFold(s, "Transfer-Encoding") {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
