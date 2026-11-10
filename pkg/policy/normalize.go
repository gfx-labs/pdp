package policy

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// This file only extracts facts from a normalized request. The embedded Rego
// policy decides what those facts are allowed to do.

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
