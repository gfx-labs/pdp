package policy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

// basePolicy makes every authorization decision. Go only validates the trusted
// envelope and extracts request facts for it.
//
//go:embed base.rego
var basePolicy string

// Custom modules may only add reasons to this set.
const customBase = "package pdp.custom\nimport rego.v1\ndeny contains \"unreachable\" if { false }"

// Engine contains only private, frozen state and prepared queries. Build a new
// Engine before atomically replacing the gateway's snapshot pointer.
type Engine struct {
	config          Config
	operations      map[string]Operation
	diagnostics     []Diagnostic
	valueSelectors  map[string]selector
	objectSelectors map[string]selector
	query           rego.PreparedEvalQuery
}

func New(ctx context.Context, config Config) (*Engine, error) {
	// Copy through JSON so caller-owned maps, slices and arbitrary JSON values
	// cannot mutate a published snapshot after validation.
	b, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode policy configuration: %w", err)
	}
	var frozen Config
	if err = decodeJSON(b, &frozen); err != nil {
		return nil, err
	}
	if strings.TrimSpace(frozen.Revision) == "" {
		return nil, errors.New("policy revision is required")
	}
	e := &Engine{config: frozen, operations: make(map[string]Operation)}
	if err = e.validate(); err != nil {
		return nil, err
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
	// The configuration is written once as data.pdp.config and never changes.
	store := inmem.NewFromObjectWithOpts(e.policyData(), inmem.OptReturnASTValuesOnRead(true))
	opts := []func(*rego.Rego){rego.Query("data.pdp.base.decision"), rego.Module("pdp-base.rego", basePolicy), rego.Module("pdp-custom-base.rego", customBase), rego.Store(store), rego.Capabilities(capabilities), rego.StrictBuiltinErrors(true)}
	for _, name := range sortedKeys(frozen.CustomModules) {
		source := frozen.CustomModules[name]
		module, parseErr := ast.ParseModuleWithOpts(name, source, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if parseErr != nil {
			return nil, fmt.Errorf("custom module %s: %w", name, parseErr)
		}
		if module.Package.Path.String() != "data.pdp.custom" {
			return nil, fmt.Errorf("custom module %s must use package pdp.custom", name)
		}
		for _, rule := range module.Rules {
			if rule.Head.Name.String() == "deny" && rule.Head.Key == nil {
				return nil, fmt.Errorf("custom module %s deny must be a set of reason strings", name)
			}
		}
		e.diagnoseCustomReferences(name, module)
		opts = append(opts, rego.ParsedModule(module))
	}
	e.query, err = rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return e, nil
}

func (e *Engine) Revision() string { return e.config.Revision }
func (e *Engine) Diagnostics() []Diagnostic {
	b, _ := json.Marshal(e.diagnostics)
	var out []Diagnostic
	_ = json.Unmarshal(b, &out)
	return out
}

type unit struct {
	operation OperationInput
	field     *FieldOccurrence
}

func (e *Engine) Evaluate(ctx context.Context, input Input) (Decision, error) {
	d := Decision{Revision: e.Revision(), Identity: input.Identity, Provider: input.Provider, Binding: input.Binding, SchemaDigest: input.SchemaDigest, Reasons: []string{}, MatchedGrants: []string{}, MatchedGrantDetails: []GrantExplanation{}, DeniedBy: []string{}, Operations: []OperationDecision{}}
	if e.config.Relationships != nil {
		d.RelationshipRevision = e.config.Relationships.Revision
	}
	if err := ctx.Err(); err != nil {
		d.Reasons = append(d.Reasons, "evaluation canceled")
		return d, err
	}
	if input.Version != InputVersion || input.Identity.ID == "" || input.Provider == "" || input.Binding == "" {
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
	// Freeze input values as JSON, both for a consistent Rego view and selectors.
	b, err := json.Marshal(input)
	if err != nil {
		d.Reasons = append(d.Reasons, "invalid input values")
		return d, err
	}
	var frozenInput Input
	if err = decodeJSON(b, &frozenInput); err != nil {
		return d, err
	}
	input = frozenInput
	d.Identity = input.Identity
	var regoInput map[string]any
	if err = decodeJSON(b, &regoInput); err != nil {
		return d, err
	}
	units, err := requestUnits(input)
	if err != nil {
		d.Reasons = append(d.Reasons, err.Error())
		return d, nil
	}
	facts := make([]any, 0, len(units))
	for _, u := range units {
		fact, resources := e.unitFacts(input, u)
		facts = append(facts, fact)
		detail := OperationDecision{ID: u.operation.ID, Resources: resources, MatchedGrants: []string{}}
		if u.field != nil {
			detail.Path = append([]string(nil), u.field.Path...)
		}
		d.Operations = append(d.Operations, detail)
	}
	regoInput["_pdp"] = map[string]any{"units": facts, "now_ns": nanos(time.Now()), "revision": e.Revision()}
	results, err := e.query.Eval(ctx, rego.EvalInput(regoInput))
	if err != nil {
		d.Reasons = append(d.Reasons, "policy evaluation failed")
		return d, fmt.Errorf("evaluate policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		d.Reasons = append(d.Reasons, "undefined policy decision")
		return d, errors.New("undefined policy decision")
	}
	// Any unexpected decision shape denies with an error.
	value, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return d, errors.New("invalid policy decision shape")
	}
	allowed, ok := value["allow"].(bool)
	if !ok {
		return d, errors.New("invalid policy allow shape")
	}
	deniedBy, ok := stringItems(value["denied_by"])
	if !ok {
		return d, errors.New("invalid policy denial shape")
	}
	reasons, ok := stringItems(value["reasons"])
	if !ok {
		return d, errors.New("invalid policy reason shape")
	}
	custom, ok := stringItems(value["custom_denials"])
	if !ok {
		return d, errors.New("custom deny must contain only reason strings")
	}
	unitResults, ok := value["units"].([]any)
	if !ok || len(unitResults) != len(units) {
		return d, errors.New("invalid policy unit shape")
	}
	matched := map[string]bool{}
	for i, item := range unitResults {
		result, valid := item.(map[string]any)
		if !valid {
			return d, errors.New("invalid policy unit shape")
		}
		grants, valid := stringItems(result["grants"])
		if !valid {
			return d, errors.New("invalid policy grant shape")
		}
		d.Operations[i].MatchedGrants = unique(grants)
		for _, id := range grants {
			matched[id] = true
		}
	}
	for _, grant := range e.config.Grants {
		if !matched[grant.ID] {
			continue
		}
		d.MatchedGrants = append(d.MatchedGrants, grant.ID)
		data, _ := json.Marshal(GrantExplanation{ID: grant.ID, Mode: grant.Mode, Operations: grant.Scope.Operations, Constraints: grant.Constraints})
		var detail GrantExplanation
		_ = decodeJSON(data, &detail)
		d.MatchedGrantDetails = append(d.MatchedGrantDetails, detail)
	}
	for _, reason := range custom {
		reasons = append(reasons, "custom deny: "+reason)
	}
	d.MatchedGrants = unique(d.MatchedGrants)
	d.DeniedBy = unique(deniedBy)
	d.Reasons = unique(reasons)
	d.Allow = allowed
	return d, nil
}

// stringItems reads a Rego set or array that must contain only strings.
func stringItems(value any) ([]string, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, valid := item.(string)
		if !valid {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func requestUnits(input Input) ([]unit, error) {
	var units []unit
	fields := map[string]bool{}
	for i := range input.GraphQL {
		field := &input.GraphQL[i]
		id := field.Coordinate
		if id == "" {
			return nil, errors.New("GraphQL field coordinate is required")
		}
		fields[id] = true
		op := OperationInput{ID: id}
		for _, candidate := range input.Operations {
			if candidate.ID == id {
				op.Resources = append(op.Resources, candidate.Resources...)
			}
		}
		units = append(units, unit{operation: op, field: field})
	}
	for _, op := range input.Operations {
		if op.ID == "" {
			return nil, errors.New("operation ID is required")
		}
		if !fields[op.ID] {
			units = append(units, unit{operation: op})
		}
	}
	if len(units) == 0 {
		return nil, errors.New("at least one normalized operation is required")
	}
	return units, nil
}

func containsOrAll(values []string, value string) bool {
	return len(values) == 0 || contains(values, value)
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func unique(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func decodeJSON(b []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	return decoder.Decode(value)
}
