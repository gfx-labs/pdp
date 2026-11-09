package policy

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"
)

func (e *Engine) resources(input Input, u unit) ([]Resource, error) {
	resources, err := e.directResources(input, u)
	if err != nil {
		return nil, err
	}
	if u.field == nil {
		return resources, nil
	}
	for i := range input.GraphQL {
		ancestor := &input.GraphQL[i]
		if len(ancestor.Path) == 0 || len(ancestor.Path) >= len(u.field.Path) {
			continue
		}
		prefix := true
		for j, part := range ancestor.Path {
			if u.field.Path[j] != part {
				prefix = false
				break
			}
		}
		if !prefix {
			continue
		}
		parent := unit{operation: OperationInput{ID: ancestor.Coordinate}, field: ancestor}
		for _, op := range input.Operations {
			if op.ID == ancestor.Coordinate {
				parent.operation.Resources = append(parent.operation.Resources, op.Resources...)
			}
		}
		inherited, err := e.directResources(input, parent)
		if err != nil {
			return nil, err
		}
		resources = append(resources, inherited...)
	}
	return resources, nil
}

func (e *Engine) directResources(input Input, u unit) ([]Resource, error) {
	resources := append([]Resource(nil), u.operation.Resources...)
	op, ok := e.operations[input.Provider+"\x00"+u.operation.ID]
	if ok {
		if len(op.Resources) > 0 && op.SchemaDigest != "" && op.SchemaDigest != input.SchemaDigest {
			return nil, fmt.Errorf("resource selector schema digest mismatch")
		}
		for _, selector := range op.Resources {
			if selector.Field != "" && (u.field == nil || selector.Field != u.field.Coordinate) {
				continue
			}
			values := selectValues(input, u, selector.Source, selector.Path, selector.Field)
			if len(selector.Components) > 0 {
				parts := make([]string, 0, len(selector.Components))
				for _, path := range selector.Components {
					selected := selectValues(input, u, selector.Source, path, selector.Field)
					if len(selected) != 1 {
						return nil, fmt.Errorf("composite resource component must yield exactly one value")
					}
					part, ok := selected[0].(string)
					if !ok || part == "" || strings.Contains(part, "/") {
						return nil, fmt.Errorf("composite resource component must be a nonempty string without slash")
					}
					parts = append(parts, part)
				}
				values = []any{strings.Join(parts, "/")}
			}
			if len(values) == 0 || (len(values) == 1 && values[0] == nil) {
				continue
			}
			for _, value := range values {
				var id string
				switch v := value.(type) {
				case string:
					id = v
				case json.Number:
					var err error
					id, err = numericResourceID(v)
					if err != nil {
						return nil, err
					}
				default:
					return nil, fmt.Errorf("resource selector %s must yield scalar IDs", selector.Type)
				}
				resources = append(resources, Resource{Type: selector.Type, ID: id})
			}
		}
	}
	for _, resource := range resources {
		if resource.Type == "" || resource.ID == "" {
			return nil, fmt.Errorf("resource type and ID are required")
		}
	}
	return resources, nil
}

func (e *Engine) constraints(c Constraints, input Input, u unit, resources []Resource, now time.Time) string {
	return e.checkConstraints(c, input, u, resources, now, false)
}

func (e *Engine) checkConstraints(c Constraints, input Input, u unit, resources []Resource, now time.Time, deny bool) string {
	if len(c.SchemaDigests) > 0 && !contains(c.SchemaDigests, input.SchemaDigest) {
		return "schema digest not allowed"
	}
	for _, restriction := range []struct {
		kind string
		ids  []string
	}{{"repository", c.Repositories}, {"issue", c.Issues}} {
		if len(restriction.ids) == 0 {
			continue
		}
		found, matched := false, false
		for _, resource := range resources {
			if resource.Type != restriction.kind {
				continue
			}
			found = true
			if contains(restriction.ids, resource.ID) {
				matched = true
			} else if !deny {
				return restriction.kind + " outside allowed list"
			}
		}
		if !found || !matched {
			return restriction.kind + " not present in allowed list"
		}
	}
	if len(c.Resources) > 0 {
		matched := false
		for _, resource := range resources {
			allowed := false
			for _, candidate := range c.Resources {
				if candidate == resource {
					allowed = true
					matched = true
					break
				}
			}
			if !allowed && !deny {
				return "resource outside allowed list"
			}
		}
		if len(resources) == 0 || !matched {
			return "no matching resource"
		}
	}
	for _, constraint := range c.Values {
		if constraint.Field != "" && (u.field == nil || constraint.Field != u.field.Coordinate) {
			if deny {
				return "field constraint does not apply"
			}
			continue
		}
		values := selectValues(input, u, constraint.Source, constraint.Path, constraint.Field)
		if len(values) == 0 {
			return "required request value missing"
		}
		matched := false
		for _, value := range values {
			if value == nil {
				if deny {
					continue
				}
				return "required request value missing"
			}
			allowed := false
			for _, candidate := range constraint.Values {
				if equalJSON(value, candidate) {
					allowed = true
					matched = true
					break
				}
			}
			if !allowed && !deny {
				return "request value outside allowed list"
			}
		}
		if !matched {
			return "request value outside allowed list"
		}
	}
	for _, constraint := range c.Objects {
		if constraint.Field != "" && (u.field == nil || constraint.Field != u.field.Coordinate) {
			if deny {
				return "object field constraint does not apply"
			}
			continue
		}
		values := selectRequestValues(input, u, constraint.Source, constraint.Path, constraint.Field, false)
		matched := false
		for _, value := range values {
			reason := objectRestriction(constraint, value)
			if reason == "" {
				matched = true
			} else if !deny {
				return reason
			}
		}
		if !matched {
			return "required constrained object missing or invalid"
		}
	}
	if c.Relationship != nil {
		return e.relationship(*c.Relationship, input, resources, now)
	}
	return ""
}

func objectRestriction(constraint ObjectConstraint, value any) string {
	object, ok := value.(map[string]any)
	if !ok {
		return "required request object missing"
	}
	for key := range object {
		if !contains(constraint.AllowedKeys, key) {
			return "request object contains a forbidden key"
		}
	}
	for _, key := range constraint.RequiredStringKeys {
		text, ok := object[key].(string)
		if !ok || strings.TrimSpace(text) == "" {
			return "request object requires nonempty string keys"
		}
	}
	return ""
}

func equalJSON(a, b any) bool {
	switch value := a.(type) {
	case json.Number:
		other, ok := b.(json.Number)
		return ok && canonicalNumber(value) == canonicalNumber(other)
	case []any:
		other, ok := b.([]any)
		if !ok || len(value) != len(other) {
			return false
		}
		for i := range value {
			if !equalJSON(value[i], other[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		other, ok := b.(map[string]any)
		if !ok || len(value) != len(other) {
			return false
		}
		for key, item := range value {
			candidate, found := other[key]
			if !found || !equalJSON(item, candidate) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(a, b)
	}
}

// Normalize decimal coefficient and exponent without materializing 10^exponent.
func canonicalNumber(number json.Number) string {
	text := number.String()
	negative := strings.HasPrefix(text, "-")
	text = strings.TrimPrefix(text, "-")
	exponent := new(big.Int)
	if at := strings.IndexAny(text, "eE"); at >= 0 {
		exponent.SetString(text[at+1:], 10)
		text = text[:at]
	}
	if at := strings.IndexByte(text, '.'); at >= 0 {
		exponent.Sub(exponent, big.NewInt(int64(len(text)-at-1)))
		text = text[:at] + text[at+1:]
	}
	text = strings.TrimLeft(text, "0")
	if text == "" {
		return "0"
	}
	trimmed := strings.TrimRight(text, "0")
	exponent.Add(exponent, big.NewInt(int64(len(text)-len(trimmed))))
	if negative {
		trimmed = "-" + trimmed
	}
	return trimmed + "e" + exponent.String()
}

func numericResourceID(number json.Number) (string, error) {
	canonical := canonicalNumber(number)
	if canonical == "0" {
		return "0", nil
	}
	at := strings.LastIndexByte(canonical, 'e')
	exponent, _ := new(big.Int).SetString(canonical[at+1:], 10)
	if exponent.Sign() < 0 || !exponent.IsInt64() || exponent.Int64() > 1024 || int64(at)+exponent.Int64() > 1024 {
		return "", fmt.Errorf("numeric resource ID must be an integer of at most 1024 digits")
	}
	return canonical[:at] + strings.Repeat("0", int(exponent.Int64())), nil
}

func (e *Engine) relationship(requirement RelationshipRequirement, input Input, resources []Resource, now time.Time) string {
	snapshot := e.config.Relationships
	if snapshot == nil {
		return "required relationship snapshot missing"
	}
	if snapshot.IssuedAt.After(now) || !snapshot.ExpiresAt.After(now) || now.Sub(snapshot.IssuedAt) > snapshot.MaxAge {
		return "required relationship snapshot expired or stale"
	}
	if input.Identity.TaskID == "" {
		return "task selection is required"
	}
	member := false
	for _, edge := range snapshot.IdentityTasks {
		if edge.Identity == input.Identity.ID && edge.Task == input.Identity.TaskID && edge.ExpiresAt.After(now) {
			member = true
			break
		}
	}
	if !member {
		return "task selection is not authorized for identity"
	}
	checked := 0
	for _, resource := range resources {
		if !containsOrAll(requirement.ResourceTypes, resource.Type) {
			continue
		}
		checked++
		allowed := false
		for _, edge := range snapshot.TaskResources {
			if edge.Task == input.Identity.TaskID && edge.Resource == resource && edge.Permission == requirement.Permission && edge.ExpiresAt.After(now) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "task lacks active resource permission"
		}
	}
	if checked == 0 {
		return "relationship requires an identified resource"
	}
	return ""
}

func selectValues(input Input, u unit, source string, path []string, field string) []any {
	return selectRequestValues(input, u, source, path, field, true)
}

func selectRequestValues(input Input, u unit, source string, path []string, field string, flatten bool) []any {
	var root any
	switch source {
	case "path":
		m := map[string]any{}
		for k, v := range input.HTTP.PathParams {
			m[k] = v
		}
		root = m
	case "query":
		if input.SchemaDigest != "" || input.HTTP.NormalizedQuery != nil {
			root = input.HTTP.NormalizedQuery
			break
		}
		m := map[string]any{}
		for k, values := range input.HTTP.Query {
			a := make([]any, len(values))
			for i, v := range values {
				a[i] = v
			}
			m[k] = a
		}
		root = m
	case "body":
		root = input.HTTP.Body
	case "variables":
		root = input.Variables
	case "graphql":
		if u.field == nil || (field != "" && u.field.Coordinate != field) {
			return nil
		}
		root = u.field.Arguments
	case "resource":
		var a []any
		for _, resource := range u.operation.Resources {
			a = append(a, map[string]any{"type": resource.Type, "id": resource.ID})
		}
		root = a
	}
	return walkValues(root, path, flatten)
}

// Wildcards select every member, never one convenient member of a collection.
func walkValues(value any, path []string, flatten bool) []any {
	if len(path) == 0 {
		if array, ok := value.([]any); ok && flatten {
			var out []any
			for _, item := range array {
				out = append(out, walkValues(item, nil, flatten)...)
			}
			return out
		}
		return []any{value}
	}
	if path[0] == "*" {
		var out []any
		switch v := value.(type) {
		case []any:
			for _, item := range v {
				out = append(out, walkValues(item, path[1:], flatten)...)
			}
		case map[string]any:
			for _, key := range sortedKeys(v) {
				out = append(out, walkValues(v[key], path[1:], flatten)...)
			}
		}
		return out
	}
	if object, ok := value.(map[string]any); ok {
		return walkValues(object[path[0]], path[1:], flatten)
	}
	return []any{nil}
}
