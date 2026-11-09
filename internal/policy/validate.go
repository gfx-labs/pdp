package policy

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

func (e *Engine) validate() error {
	for _, op := range e.config.Operations {
		if op.ID == "" || op.Provider == "" {
			return fmt.Errorf("operation requires ID and provider")
		}
		if strings.HasPrefix(op.ID, "untyped:") {
			return fmt.Errorf("operation %s uses reserved schema-free namespace", op.ID)
		}
		key := op.Provider + "\x00" + op.ID
		if _, exists := e.operations[key]; exists {
			return fmt.Errorf("duplicate operation %s for %s", op.ID, op.Provider)
		}
		switch op.Classification {
		case ReadOperation, WriteOperation, DestructiveOperation, AdminOperation:
		default:
			return fmt.Errorf("operation %s has invalid classification", op.ID)
		}
		for _, selector := range op.Resources {
			if selector.Type == "" {
				return fmt.Errorf("operation %s resource selector type required", op.ID)
			}
			if err := validateSelector(selector.Source, selector.Path, selector.Field); err != nil {
				return fmt.Errorf("operation %s: %w", op.ID, err)
			}
			if len(selector.Components) > 0 {
				if len(selector.Components) < 2 || len(selector.Path) != 0 {
					return fmt.Errorf("operation %s: resource components require at least two paths and no path", op.ID)
				}
				for _, path := range selector.Components {
					if len(path) == 0 {
						return fmt.Errorf("operation %s: empty resource component path", op.ID)
					}
					if err := validateSelector(selector.Source, path, selector.Field); err != nil {
						return err
					}
				}
			}
		}
		e.operations[key] = op
		if !op.Reviewed {
			e.diagnostics = append(e.diagnostics, Diagnostic{Code: "unreviewed_operation", Message: "operation " + op.ID + " cannot satisfy restricted grants"})
		}
	}
	ids := map[string]bool{}
	validateRule := func(id string, scope Scope, c Constraints) error {
		if strings.TrimSpace(id) == "" || ids[id] {
			return fmt.Errorf("rule ID must be nonempty and unique: %q", id)
		}
		ids[id] = true
		for _, values := range [][]string{scope.Identities, scope.Providers, scope.Bindings, scope.Operations, c.Repositories, c.Issues, c.SchemaDigests} {
			for _, value := range values {
				if strings.TrimSpace(value) == "" || value == "*" {
					return fmt.Errorf("rule %s: empty and wildcard scope/list values are forbidden", id)
				}
			}
		}
		for _, resource := range c.Resources {
			if resource.Type == "" || resource.ID == "" {
				return fmt.Errorf("rule %s: resource type and ID required", id)
			}
		}
		for _, constraint := range c.Values {
			if err := validateSelector(constraint.Source, constraint.Path, constraint.Field); err != nil {
				return fmt.Errorf("rule %s: %w", id, err)
			}
			if len(constraint.Values) == 0 {
				return fmt.Errorf("rule %s: value constraint needs allowed values", id)
			}
		}
		if c.Relationship != nil {
			if c.Relationship.Permission == "" {
				return fmt.Errorf("rule %s relationship permission required", id)
			}
			for _, kind := range c.Relationship.ResourceTypes {
				if kind == "" {
					return fmt.Errorf("rule %s relationship resource type required", id)
				}
			}
		}
		for _, operation := range scope.Operations {
			found := false
			for _, op := range e.config.Operations {
				if op.ID == operation && containsOrAll(scope.Providers, op.Provider) {
					found = true
					break
				}
			}
			if !found {
				e.diagnostics = append(e.diagnostics, Diagnostic{Code: "unknown_operation_reference", Message: "rule " + id + " references unregistered operation " + operation, Rules: []string{id}})
			}
		}
		return nil
	}
	for _, g := range e.config.Grants {
		if len(g.Scope.Identities) == 0 || len(g.Scope.Providers) == 0 || len(g.Scope.Bindings) == 0 {
			return fmt.Errorf("grant %s requires explicit identities, providers and bindings", g.ID)
		}
		switch g.Mode {
		case Full, Read, ReadWrite:
		case "":
			if len(g.Scope.Operations) == 0 {
				return fmt.Errorf("grant %s requires mode or explicit operations", g.ID)
			}
		default:
			return fmt.Errorf("grant %s: unknown mode %q", g.ID, g.Mode)
		}
		if err := validateRule(g.ID, g.Scope, g.Constraints); err != nil {
			return err
		}
	}
	for _, rules := range [][]Rule{e.config.Denies, e.config.Mandatory} {
		for _, r := range rules {
			if err := validateRule(r.ID, r.Scope, r.Constraints); err != nil {
				return err
			}
		}
	}
	for _, deny := range e.config.Denies {
		if deny.Constraints.Relationship != nil {
			return fmt.Errorf("deny %s: relationship requirements belong in grants or mandatory rules", deny.ID)
		}
	}
	for i, a := range e.config.Grants {
		for _, b := range e.config.Grants[i+1:] {
			if scopesOverlap(a.Scope, b.Scope) {
				e.diagnostics = append(e.diagnostics, Diagnostic{Code: "overlapping_grants", Message: "grants overlap in scope, each grant's constraints remain independent", Rules: []string{a.ID, b.ID}})
			}
		}
	}
	if s := e.config.Relationships; s != nil {
		if s.Revision == "" || s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.IssuedAt) || s.MaxAge <= 0 {
			return fmt.Errorf("relationship snapshot needs revision, ordered timestamps and positive max_age")
		}
		for _, edge := range s.IdentityTasks {
			if edge.Identity == "" || edge.Task == "" || edge.ExpiresAt.IsZero() {
				return fmt.Errorf("identity-task edge requires identity, task and expiry")
			}
		}
		for _, edge := range s.TaskResources {
			if edge.Task == "" || edge.Resource.Type == "" || edge.Resource.ID == "" || edge.Permission == "" || edge.ExpiresAt.IsZero() {
				return fmt.Errorf("task-resource edge requires task, resource, permission and expiry")
			}
		}
	}
	return nil
}

// Only literal comparisons are statically decidable. Dynamic Rego expressions
// still constrain authorization, but cannot be exhaustively reference-checked.
func (e *Engine) diagnoseCustomReferences(name string, module *ast.Module) {
	ast.WalkExprs(module, func(expr *ast.Expr) bool {
		operator := expr.Operator().String()
		if operator != ast.Equal.Name && operator != ast.Equality.Name && operator != ast.NotEqual.Name {
			return false
		}
		operands := expr.Operands()
		if len(operands) != 2 {
			return false
		}
		for side, operand := range operands {
			literal, ok := operand.Value.(ast.String)
			if !ok {
				continue
			}
			operationRef := false
			ast.WalkRefs(operands[1-side], func(ref ast.Ref) bool {
				if len(ref) < 3 || ref[0].String() != "input" {
					return false
				}
				root, _ := ref[1].Value.(ast.String)
				leaf, _ := ref[len(ref)-1].Value.(ast.String)
				if (root == "operations" && leaf == "id") || (root == "graphql" && leaf == "coordinate") {
					operationRef = true
				}
				return false
			})
			if !operationRef {
				continue
			}
			known := false
			for _, op := range e.config.Operations {
				if op.ID == string(literal) {
					known = true
					break
				}
			}
			if !known {
				e.diagnostics = append(e.diagnostics, Diagnostic{Code: "unknown_operation_reference", Message: "custom module " + name + " references unregistered operation " + string(literal), Rules: []string{name}})
			}
		}
		return false
	})
}

func validateSelector(source string, path []string, field string) error {
	switch source {
	case "path", "query", "body", "graphql", "variables", "resource":
	default:
		return fmt.Errorf("unknown selector source %q", source)
	}
	if field != "" && source != "graphql" {
		return fmt.Errorf("field selector requires graphql source")
	}
	for _, part := range path {
		if part == "" {
			return fmt.Errorf("selector path segments cannot be empty")
		}
	}
	return nil
}

func scopesOverlap(a, b Scope) bool {
	intersects := func(a, b []string) bool {
		if len(a) == 0 || len(b) == 0 {
			return true
		}
		for _, value := range a {
			if contains(b, value) {
				return true
			}
		}
		return false
	}
	return intersects(a.Identities, b.Identities) && intersects(a.Providers, b.Providers) && intersects(a.Bindings, b.Bindings) && intersects(a.Operations, b.Operations)
}
