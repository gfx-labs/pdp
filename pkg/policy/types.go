// Package policy evaluates immutable administrator-authored Rego snapshots.
// Identity, binding, provider and schema metadata come from the trusted gateway.
package policy

const InputVersion = "pdp.authz/v1"

type Identity struct {
	ID         string  `json:"id"`
	AuthMethod string  `json:"auth_method,omitempty"`
	SPIFFEID   string  `json:"spiffe_id,omitempty"`
	UID        *uint32 `json:"uid,omitempty"`
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

type Input struct {
	Version       string            `json:"version"`
	Identity      Identity          `json:"identity"`
	Provider      string            `json:"provider"`
	Binding       string            `json:"binding"`
	SchemaDigest  string            `json:"schema_digest"`
	HTTP          HTTPInput         `json:"http"`
	Operations    []OperationInput  `json:"operations"`
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
	Provider     string              `json:"provider"`
	Binding      string              `json:"binding"`
	SchemaDigest string              `json:"schema_digest,omitempty"`
	Revision     string              `json:"revision"`
	Reasons      []string            `json:"reasons"`
	MatchedRules []string            `json:"matched_rules"`
	Operations   []OperationDecision `json:"operations"`
}
