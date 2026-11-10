package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// selector names request values a constraint reads. The engine extracts them
// per unit, since Rego cannot walk wildcard paths recursively.
type selector struct {
	Source string
	Path   []string
	Field  string
}

func selectorKey(s selector) string {
	b, _ := json.Marshal([]any{s.Source, append([]string{}, s.Path...), s.Field})
	return string(b)
}

func stringList(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func resourceData(resource Resource) map[string]any {
	return map[string]any{"type": resource.Type, "id": resource.ID}
}

var (
	minNanoTime = time.Unix(0, math.MinInt64)
	maxNanoTime = time.Unix(0, math.MaxInt64)
)

// nanos saturates outside the int64 nanosecond range instead of wrapping.
func nanos(t time.Time) json.Number {
	n := t.UnixNano()
	if t.Before(minNanoTime) {
		n = math.MinInt64
	} else if t.After(maxNanoTime) {
		n = math.MaxInt64
	}
	return json.Number(strconv.FormatInt(n, 10))
}

// canonicalKey encodes a JSON value so equal values share one key. Numbers use
// their exact mathematical value, so 1, 1.0 and 1e0 are one key.
func canonicalKey(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case json.Number:
		return canonicalNumber(v)
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, canonicalKey(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		parts := make([]string, 0, len(v))
		for _, key := range sortedKeys(v) {
			name, _ := json.Marshal(key)
			parts = append(parts, string(name)+":"+canonicalKey(v[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("!%T", v)
		}
		return string(b)
	}
}

func scopeData(s Scope) map[string]any {
	return map[string]any{"identities": stringList(s.Identities), "providers": stringList(s.Providers), "bindings": stringList(s.Bindings), "operations": stringList(s.Operations)}
}

// constraintsData always emits every key, so the policy never reads an
// undefined configuration field.
func (e *Engine) constraintsData(c Constraints) map[string]any {
	resources := make([]any, 0, len(c.Resources))
	for _, resource := range c.Resources {
		resources = append(resources, resourceData(resource))
	}
	values := make([]any, 0, len(c.Values))
	for _, constraint := range c.Values {
		s := selector{Source: constraint.Source, Path: constraint.Path, Field: constraint.Field}
		key := selectorKey(s)
		e.valueSelectors[key] = s
		allowed := make([]any, 0, len(constraint.Values))
		for _, value := range constraint.Values {
			allowed = append(allowed, canonicalKey(value))
		}
		values = append(values, map[string]any{"selector": key, "field": constraint.Field, "allowed": allowed})
	}
	objects := make([]any, 0, len(c.Objects))
	for _, constraint := range c.Objects {
		s := selector{Source: constraint.Source, Path: constraint.Path, Field: constraint.Field}
		key := selectorKey(s)
		e.objectSelectors[key] = s
		objects = append(objects, map[string]any{"selector": key, "field": constraint.Field, "allowed_keys": stringList(constraint.AllowedKeys), "required_string_keys": stringList(constraint.RequiredStringKeys)})
	}
	var relationship any
	if c.Relationship != nil {
		relationship = map[string]any{"permission": c.Relationship.Permission, "resource_types": stringList(c.Relationship.ResourceTypes)}
	}
	return map[string]any{"schema_digests": stringList(c.SchemaDigests), "repositories": stringList(c.Repositories), "issues": stringList(c.Issues), "resources": resources, "values": values, "objects": objects, "relationship": relationship}
}

// policyData is the configuration document the base policy reads at
// data.pdp.config. It is built once and never written again.
func (e *Engine) policyData() map[string]any {
	e.valueSelectors, e.objectSelectors = map[string]selector{}, map[string]selector{}
	grants := make([]any, 0, len(e.config.Grants))
	for _, grant := range e.config.Grants {
		grants = append(grants, map[string]any{"id": grant.ID, "mode": string(grant.Mode), "scope": scopeData(grant.Scope), "constraints": e.constraintsData(grant.Constraints)})
	}
	rules := func(in []Rule) []any {
		out := make([]any, 0, len(in))
		for _, rule := range in {
			out = append(out, map[string]any{"id": rule.ID, "scope": scopeData(rule.Scope), "constraints": e.constraintsData(rule.Constraints)})
		}
		return out
	}
	operations := map[string]any{}
	for _, op := range e.config.Operations {
		provider, _ := operations[op.Provider].(map[string]any)
		if provider == nil {
			provider = map[string]any{}
			operations[op.Provider] = provider
		}
		provider[op.ID] = map[string]any{"reviewed": op.Reviewed, "classification": string(op.Classification), "schema_digest": op.SchemaDigest, "constraints": e.constraintsData(op.Constraints)}
	}
	var relationships any
	if s := e.config.Relationships; s != nil {
		memberships := make([]any, 0, len(s.IdentityTasks))
		for _, edge := range s.IdentityTasks {
			memberships = append(memberships, map[string]any{"identity": edge.Identity, "task": edge.Task, "expires_at_ns": nanos(edge.ExpiresAt)})
		}
		permissions := make([]any, 0, len(s.TaskResources))
		for _, edge := range s.TaskResources {
			permissions = append(permissions, map[string]any{"task": edge.Task, "resource": resourceData(edge.Resource), "permission": edge.Permission, "expires_at_ns": nanos(edge.ExpiresAt)})
		}
		relationships = map[string]any{"revision": s.Revision, "issued_at_ns": nanos(s.IssuedAt), "expires_at_ns": nanos(s.ExpiresAt), "max_age_ns": json.Number(strconv.FormatInt(int64(s.MaxAge), 10)), "identity_tasks": memberships, "task_resources": permissions}
	}
	config := map[string]any{"revision": e.config.Revision, "grants": grants, "denies": rules(e.config.Denies), "mandatory": rules(e.config.Mandatory), "operations": operations, "relationships": relationships}
	config["value_selectors"] = stringList(sortedKeys(e.valueSelectors))
	config["object_selectors"] = stringList(sortedKeys(e.objectSelectors))
	return map[string]any{"pdp": map[string]any{"config": config}}
}

// unitFacts extracts what one unit requests. It decides nothing.
func (e *Engine) unitFacts(input Input, u unit) (map[string]any, []Resource) {
	resources, err := e.resources(input, u)
	fact := map[string]any{"id": u.operation.ID, "coordinate": "", "resource_error": ""}
	if u.field != nil {
		fact["coordinate"] = u.field.Coordinate
	}
	if err != nil {
		fact["resource_error"] = err.Error()
		resources = nil
	}
	list := make([]any, 0, len(resources))
	for _, resource := range resources {
		list = append(list, resourceData(resource))
	}
	fact["resources"] = list
	values := make(map[string]any, len(e.valueSelectors))
	for key, s := range e.valueSelectors {
		keys := []any{}
		for _, value := range selectValues(input, u, s.Source, s.Path, s.Field) {
			keys = append(keys, canonicalKey(value))
		}
		values[key] = keys
	}
	fact["values"] = values
	objects := make(map[string]any, len(e.objectSelectors))
	for key, s := range e.objectSelectors {
		objects[key] = append([]any{}, selectRequestValues(input, u, s.Source, s.Path, s.Field, false)...)
	}
	fact["objects"] = objects
	return fact, resources
}
