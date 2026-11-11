// Package policy evaluates immutable administrator-authored Rego snapshots.
// Identity, destination, binding and schema metadata come from the trusted gateway.
package policy

const InputVersion = "pdp.authz/v2"

// Protocols the gateway can report. A tunnel carries bytes the gateway cannot read.
const (
	ProtocolHTTP      = "http"
	ProtocolWebSocket = "websocket"
	ProtocolTunnel    = "tunnel"
)

// Identity holds facts the gateway verified. IP is set only for callers that
// arrived on a transparent listener, where the source address is all there is.
type Identity struct {
	ID         string  `json:"id"`
	AuthMethod string  `json:"auth_method,omitempty"`
	SPIFFEID   string  `json:"spiffe_id,omitempty"`
	UID        *uint32 `json:"uid,omitempty"`
	IP         string  `json:"ip,omitempty"`
}

// Destination is where the gateway will connect. Host is lower case without a
// trailing dot. Addresses are the exact addresses it will dial. They are absent
// on the evaluation that runs before a DNS lookup.
type Destination struct {
	Scheme    string   `json:"scheme"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Addresses []string `json:"addresses,omitempty"`
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type HTTPInput struct {
	Method          string              `json:"method"`
	Path            string              `json:"path"`
	PathParams      map[string]string   `json:"path_params,omitempty"`
	Query           map[string][]string `json:"query,omitempty"`
	NormalizedQuery map[string]any      `json:"normalized_query,omitempty"`
	Body            any                 `json:"body,omitempty"`
}

// FieldOccurrence remains a list entry, including when aliases or arguments repeat.
type FieldOccurrence struct {
	Coordinate   string         `json:"coordinate"`
	Path         []string       `json:"path"`
	ResponsePath []string       `json:"response_path,omitempty"`
	ParentType   string         `json:"parent_type,omitempty"`
	Field        string         `json:"field,omitempty"`
	Alias        string         `json:"alias,omitempty"`
	Arguments    map[string]any `json:"arguments"`
}

type OperationInput struct {
	ID        string     `json:"id"`
	Resources []Resource `json:"resources,omitempty"`
}

// Input is generic for every destination. Plugin, SchemaDigest, Operations and
// the schema-derived HTTP fields are set only when the upstream pins a schema.
// Binding is empty when no credential will be injected. HTTP is nil for a tunnel.
type Input struct {
	Version       string            `json:"version"`
	Identity      Identity          `json:"identity"`
	Protocol      string            `json:"protocol"`
	Destination   Destination       `json:"destination"`
	Binding       string            `json:"binding,omitempty"`
	Plugin        string            `json:"plugin,omitempty"`
	SchemaDigest  string            `json:"schema_digest,omitempty"`
	HTTP          *HTTPInput        `json:"http,omitempty"`
	Operations    []OperationInput  `json:"operations,omitempty"`
	GraphQL       []FieldOccurrence `json:"graphql,omitempty"`
	OperationType string            `json:"operation_type,omitempty"`
	OperationName string            `json:"operation_name,omitempty"`
	Variables     map[string]any    `json:"variables,omitempty"`
}

// Config contains source modules in package pdp.authz and optional standard OPA data.
// Data cannot define or shadow data.pdp.authz. Go assigns no meaning to other data.
type Config struct {
	Revision string            `json:"revision"`
	Modules  map[string]string `json:"modules"`
	Data     map[string]any    `json:"data,omitempty"`
}

type Diagnostic struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Rules   []string `json:"rules,omitempty"`
}

type OperationDecision struct {
	ID        string     `json:"id"`
	Path      []string   `json:"path,omitempty"`
	Resources []Resource `json:"resources,omitempty"`
}

type Decision struct {
	Allow        bool                `json:"allow"`
	Identity     Identity            `json:"identity"`
	Protocol     string              `json:"protocol"`
	Destination  Destination         `json:"destination"`
	Binding      string              `json:"binding,omitempty"`
	SchemaDigest string              `json:"schema_digest,omitempty"`
	Revision     string              `json:"revision"`
	Reasons      []string            `json:"reasons"`
	MatchedRules []string            `json:"matched_rules"`
	Operations   []OperationDecision `json:"operations"`
}
