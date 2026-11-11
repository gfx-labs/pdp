package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// Engine contains only private, frozen state and a prepared query. Build a new
// Engine before atomically replacing the gateway's snapshot pointer.
type Engine struct {
	revision string
	query    rego.PreparedEvalQuery
}

func New(ctx context.Context, config Config) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// JSON freezing prevents caller-owned maps and slices from mutating a snapshot.
	b, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode policy configuration: %w", err)
	}
	var frozen Config
	if err := decodeJSON(b, &frozen); err != nil {
		return nil, fmt.Errorf("decode policy configuration: %w", err)
	}
	if strings.TrimSpace(frozen.Revision) == "" {
		return nil, errors.New("policy revision is required")
	}
	if len(frozen.Modules) == 0 {
		return nil, errors.New("at least one policy module is required")
	}
	if pdp, exists := frozen.Data["pdp"]; exists {
		object, ok := pdp.(map[string]any)
		if !ok {
			return nil, errors.New("policy data.pdp must be an object")
		}
		if _, exists := object["authz"]; exists {
			return nil, errors.New("policy data must not define data.pdp.authz")
		}
	}
	capabilities := ast.CapabilitiesForThisVersion()
	builtins := capabilities.Builtins[:0]
	for _, builtin := range capabilities.Builtins {
		switch builtin.Name {
		case "http.send", "net.lookup_ip_addr", "opa.runtime":
			continue
		}
		builtins = append(builtins, builtin)
	}
	capabilities.Builtins = builtins
	capabilities.AllowNet = []string{}
	data := frozen.Data
	if data == nil {
		data = map[string]any{}
	}
	store := inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))
	opts := []func(*rego.Rego){
		rego.Query("data.pdp.authz"),
		rego.Store(store),
		rego.Capabilities(capabilities),
		rego.StrictBuiltinErrors(true),
	}
	names := make([]string, 0, len(frozen.Modules))
	for name := range frozen.Modules {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		source := frozen.Modules[name]
		if strings.TrimSpace(name) == "" || strings.TrimSpace(source) == "" {
			return nil, errors.New("policy module name and source must be nonempty")
		}
		module, err := ast.ParseModuleWithOpts(name, source, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parse policy module %s: %w", name, err)
		}
		if module.Package.Path.String() != "data.pdp.authz" {
			return nil, fmt.Errorf("policy module %s must use package pdp.authz", name)
		}
		opts = append(opts, rego.ParsedModule(module))
	}
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{revision: frozen.Revision, query: query}, nil
}

func (e *Engine) Revision() string { return e.revision }

// Diagnostics does not interpret or infer permissions from administrator source.
func (e *Engine) Diagnostics() []Diagnostic { return []Diagnostic{} }

func (e *Engine) Evaluate(ctx context.Context, input Input) (Decision, error) {
	d := Decision{
		Revision: e.Revision(), Identity: input.Identity, Protocol: input.Protocol,
		Destination: input.Destination, Binding: input.Binding, SchemaDigest: input.SchemaDigest,
		Reasons: []string{}, MatchedRules: []string{}, Operations: []OperationDecision{},
	}
	// Do not retain the caller's UID pointer, including on an invalid input path.
	if input.Identity.UID != nil {
		uid := *input.Identity.UID
		d.Identity.UID = &uid
	}
	if err := ctx.Err(); err != nil {
		d.Reasons = append(d.Reasons, "evaluation canceled")
		return d, err
	}
	d.Destination.Addresses = append([]string(nil), input.Destination.Addresses...)
	if !validEnvelope(input) {
		d.Reasons = append(d.Reasons, "invalid trusted input envelope")
		return d, nil
	}
	if input.SchemaDigest != "" {
		for key := range input.HTTP.Query {
			if _, present := input.HTTP.NormalizedQuery[key]; !present {
				d.Reasons = append(d.Reasons, "schema-backed query normalization is incomplete")
				return d, nil
			}
		}
	}
	b, err := json.Marshal(input)
	if err != nil {
		d.Reasons = append(d.Reasons, "invalid input values")
		return d, fmt.Errorf("encode policy input: %w", err)
	}
	var frozen Input
	if err := decodeJSON(b, &frozen); err != nil {
		return d, fmt.Errorf("decode policy input: %w", err)
	}
	d.Identity = frozen.Identity
	d.Operations, err = operationDetails(frozen)
	if err != nil {
		d.Reasons = append(d.Reasons, err.Error())
		return d, nil
	}
	var regoInput map[string]any
	if err := decodeJSON(b, &regoInput); err != nil {
		return d, fmt.Errorf("decode policy input: %w", err)
	}
	results, err := e.query.Eval(ctx, rego.EvalInput(regoInput))
	if err != nil {
		d.Reasons = append(d.Reasons, "policy evaluation failed")
		return d, fmt.Errorf("evaluate policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return d, errors.New("undefined policy decision")
	}
	value, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return d, errors.New("invalid policy decision shape")
	}
	allowed, ok := value["allow"].(bool)
	if !ok {
		return d, errors.New("policy allow must be a boolean")
	}
	reasons, ok := stringItems(value, "reasons")
	if !ok {
		return d, errors.New("policy reasons must contain only strings")
	}
	matched, ok := stringItems(value, "matched_rules")
	if !ok {
		return d, errors.New("policy matched_rules must contain only strings")
	}
	// Assign allow last so every malformed optional field also fails closed.
	d.Reasons, d.MatchedRules, d.Allow = reasons, matched, allowed
	return d, nil
}

// validEnvelope checks the shape the gateway promises, not any permission.
func validEnvelope(input Input) bool {
	if input.Version != InputVersion || input.Identity.ID == "" || input.Destination.Host == "" || input.Destination.Port < 1 || input.Destination.Port > 65535 {
		return false
	}
	switch input.Protocol {
	case ProtocolHTTP, ProtocolWebSocket:
		if input.HTTP == nil || (input.Destination.Scheme != "http" && input.Destination.Scheme != "https") {
			return false
		}
	case ProtocolTunnel:
		if input.HTTP != nil || input.Destination.Scheme != "tcp" || input.Plugin != "" || input.Binding != "" {
			return false
		}
	default:
		return false
	}
	// A schema-backed request without a digest or operation was not normalized.
	if (input.Plugin == "") != (input.SchemaDigest == "") {
		return false
	}
	return input.Plugin == "" || len(input.Operations) > 0
}

// OPA represents both sets and arrays as JSON arrays at the result boundary.
func stringItems(value map[string]any, key string) ([]string, bool) {
	items, exists := value[key]
	if !exists {
		return []string{}, true
	}
	array, ok := items.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(array))
	seen := map[string]bool{}
	for _, item := range array {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		if !seen[text] {
			out = append(out, text)
			seen[text] = true
		}
	}
	sort.Strings(out)
	return out, true
}

// operationDetails formats trusted occurrences without deriving policy facts.
func operationDetails(input Input) ([]OperationDecision, error) {
	resources := map[string][]Resource{}
	for _, op := range input.Operations {
		if op.ID == "" {
			return nil, errors.New("operation ID is required")
		}
		for _, resource := range op.Resources {
			if resource.Type == "" || resource.ID == "" {
				return nil, errors.New("resource type and ID are required")
			}
		}
		resources[op.ID] = append(resources[op.ID], op.Resources...)
	}
	out := make([]OperationDecision, 0, len(input.GraphQL)+len(input.Operations))
	fields := map[string]bool{}
	for _, field := range input.GraphQL {
		if field.Coordinate == "" {
			return nil, errors.New("GraphQL field coordinate is required")
		}
		fields[field.Coordinate] = true
		out = append(out, OperationDecision{
			ID: field.Coordinate, Path: append([]string(nil), field.Path...),
			Resources: append([]Resource(nil), resources[field.Coordinate]...),
		})
	}
	for _, op := range input.Operations {
		if !fields[op.ID] {
			out = append(out, OperationDecision{ID: op.ID, Resources: op.Resources})
		}
	}
	return out, nil
}

func decodeJSON(b []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	return decoder.Decode(value)
}
