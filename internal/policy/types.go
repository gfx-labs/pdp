// Package policy evaluates immutable authorization snapshots. All Input identity,
// binding, provider and schema metadata must be supplied by the trusted gateway.
package policy

import "time"

const InputVersion = "pdp.authz/v1"

type Identity struct {
	ID         string  `json:"id"`
	TaskID     string  `json:"task_id,omitempty"`
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

type Mode string

const (
	Full      Mode = "full"
	Read      Mode = "read"
	ReadWrite Mode = "read_write"
)

type Classification string

const (
	ReadOperation        Classification = "read"
	WriteOperation       Classification = "write"
	DestructiveOperation Classification = "destructive"
	AdminOperation       Classification = "admin"
)

// Operation is reviewed configuration, never inferred from a name or HTTP verb.
type Operation struct {
	ID             string             `json:"id"`
	Provider       string             `json:"provider"`
	SchemaDigest   string             `json:"schema_digest,omitempty"`
	Classification Classification     `json:"classification"`
	Reviewed       bool               `json:"reviewed"`
	Resources      []ResourceSelector `json:"resources,omitempty"`
	Constraints    Constraints        `json:"constraints,omitempty"`
}

// ObjectConstraint limits each selected object without merging field occurrences.
type ObjectConstraint struct {
	Source             string   `json:"source"`
	Path               []string `json:"path"`
	Field              string   `json:"field,omitempty"`
	AllowedKeys        []string `json:"allowed_keys"`
	RequiredStringKeys []string `json:"required_string_keys,omitempty"`
}

// ValueConstraint selects request values. Every selected value must be in Values.
// Missing values deny. Sources are path, query, body, graphql, variables and resource.
// Field limits a graphql selector to a schema coordinate, not an alias.
type ValueConstraint struct {
	Source string   `json:"source"`
	Path   []string `json:"path"`
	Field  string   `json:"field,omitempty"`
	Values []any    `json:"values"`
}

type ResourceSelector struct {
	Type       string     `json:"type"`
	Source     string     `json:"source"`
	Path       []string   `json:"path"`
	Components [][]string `json:"components,omitempty"`
	Field      string     `json:"field,omitempty"`
}

type RelationshipRequirement struct {
	Permission    string   `json:"permission"`
	ResourceTypes []string `json:"resource_types,omitempty"`
}

type Constraints struct {
	Repositories  []string                 `json:"repositories,omitempty"`
	Issues        []string                 `json:"issues,omitempty"`
	Resources     []Resource               `json:"resources,omitempty"`
	Values        []ValueConstraint        `json:"values,omitempty"`
	Objects       []ObjectConstraint       `json:"objects,omitempty"`
	SchemaDigests []string                 `json:"schema_digests,omitempty"`
	Relationship  *RelationshipRequirement `json:"relationship,omitempty"`
}

// Scope empty lists match all, except grants must name at least one identity,
// provider and binding. Operations are unioned only within this single scope.
type Scope struct {
	Identities []string `json:"identities,omitempty"`
	Providers  []string `json:"providers,omitempty"`
	Bindings   []string `json:"bindings,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type Grant struct {
	ID          string      `json:"id"`
	Scope       Scope       `json:"scope"`
	Mode        Mode        `json:"mode,omitempty"`
	Constraints Constraints `json:"constraints,omitempty"`
}

type Rule struct {
	ID          string      `json:"id"`
	Scope       Scope       `json:"scope"`
	Constraints Constraints `json:"constraints,omitempty"`
}

type IdentityTask struct {
	Identity  string    `json:"identity"`
	Task      string    `json:"task"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TaskResource struct {
	Task       string    `json:"task"`
	Resource   Resource  `json:"resource"`
	Permission string    `json:"permission"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RelationshipSnapshot is a fixed identity->task->resource graph, not a query API.
type RelationshipSnapshot struct {
	Revision      string         `json:"revision"`
	IssuedAt      time.Time      `json:"issued_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	MaxAge        time.Duration  `json:"max_age"`
	IdentityTasks []IdentityTask `json:"identity_tasks"`
	TaskResources []TaskResource `json:"task_resources"`
}

type Config struct {
	Revision      string                `json:"revision"`
	Operations    []Operation           `json:"operations,omitempty"`
	Grants        []Grant               `json:"grants,omitempty"`
	Denies        []Rule                `json:"denies,omitempty"`
	Mandatory     []Rule                `json:"mandatory,omitempty"`
	Relationships *RelationshipSnapshot `json:"relationships,omitempty"`
	// Each module must define package pdp.custom and deny as a set of strings.
	// Modules cannot grant access or replace the embedded base policy.
	CustomModules map[string]string `json:"custom_modules,omitempty"`
}

type Diagnostic struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Rules   []string `json:"rules,omitempty"`
}

type OperationDecision struct {
	ID            string     `json:"id"`
	Path          []string   `json:"path,omitempty"`
	Resources     []Resource `json:"resources,omitempty"`
	MatchedGrants []string   `json:"matched_grants"`
}

type GrantExplanation struct {
	ID          string      `json:"id"`
	Mode        Mode        `json:"mode,omitempty"`
	Operations  []string    `json:"operations,omitempty"`
	Constraints Constraints `json:"constraints"`
}

type Decision struct {
	Allow                bool                `json:"allow"`
	Identity             Identity            `json:"identity"`
	Provider             string              `json:"provider"`
	Binding              string              `json:"binding"`
	SchemaDigest         string              `json:"schema_digest,omitempty"`
	Revision             string              `json:"revision"`
	RelationshipRevision string              `json:"relationship_revision,omitempty"`
	Reasons              []string            `json:"reasons"`
	MatchedGrants        []string            `json:"matched_grants"`
	MatchedGrantDetails  []GrantExplanation  `json:"matched_grant_details"`
	DeniedBy             []string            `json:"denied_by"`
	Operations           []OperationDecision `json:"operations"`
}
