package config

import (
	"errors"
	"reflect"

	"github.com/gfx-labs/pdp/pkg/policy"
	"github.com/gfx-labs/pdp/pkg/schema"
)

func member(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// validateReferences prevents a typed deny from silently becoming ineffective
// when an administrator removes a route's schema or misspells an operation.
func validateReferences(c *Config, catalogs map[string]schema.Catalog) error {
	routes := make(map[string]Route)
	for _, r := range c.Routes {
		if _, exists := routes[r.Provider]; exists {
			return errors.New("duplicate provider route")
		}
		routes[r.Provider] = r
	}
	for i := range c.Policy.Operations {
		op := &c.Policy.Operations[i]
		r, ok := routes[op.Provider]
		catalog, pinned := catalogs[r.Schema]
		if !ok || !pinned || !catalog.HasOperation(op.ID) {
			return errors.New("policy operation does not exist in its provider schema")
		}
		if op.SchemaDigest == "" || op.SchemaDigest != catalog.Digest {
			return errors.New("policy operation requires its explicitly reviewed schema digest")
		}
		for _, selector := range op.Resources {
			if selector.Field != "" && !catalog.HasOperation(selector.Field) {
				return errors.New("resource selector references an unknown GraphQL field")
			}
		}
		if err := constraintFields(catalog, op.Constraints); err != nil {
			return err
		}
	}
	check := func(scope policy.Scope, constraints policy.Constraints, restricted bool) error {
		for _, provider := range scope.Providers {
			if _, ok := routes[provider]; !ok {
				return errors.New("policy references an unknown provider route")
			}
		}
		for _, binding := range scope.Bindings {
			found := false
			for _, r := range routes {
				if r.Binding == binding && (len(scope.Providers) == 0 || member(scope.Providers, r.Provider)) {
					found = true
				}
			}
			if !found {
				return errors.New("policy references an unknown route binding")
			}
		}
		for provider, r := range routes {
			if len(scope.Providers) > 0 && !member(scope.Providers, provider) {
				continue
			}
			if len(scope.Bindings) > 0 && !member(scope.Bindings, r.Binding) {
				continue
			}
			needsSchema := restricted || len(scope.Operations) > 0 || !reflect.DeepEqual(constraints, policy.Constraints{})
			catalog, pinned := catalogs[r.Schema]
			if needsSchema && !pinned {
				return errors.New("restricted policy requires a pinned route schema")
			}
			if restricted {
				reviewed := false
				for _, op := range c.Policy.Operations {
					if op.Provider == provider && op.Reviewed && op.SchemaDigest == catalog.Digest {
						reviewed = true
					}
				}
				if !reviewed {
					return errors.New("restricted profile has no reviewed operations for the pinned schema")
				}
			}
			for _, op := range scope.Operations {
				if !catalog.HasOperation(op) {
					return errors.New("policy scope references an unknown operation")
				}
			}
			if err := constraintFields(catalog, constraints); err != nil {
				return err
			}
			for _, digest := range constraints.SchemaDigests {
				if digest != catalog.Digest {
					return errors.New("policy constraint references an unpinned schema digest")
				}
			}
		}
		return nil
	}
	for _, g := range c.Policy.Grants {
		if err := check(g.Scope, g.Constraints, g.Mode == policy.Read || g.Mode == policy.ReadWrite); err != nil {
			return err
		}
	}
	for _, rules := range [][]policy.Rule{c.Policy.Denies, c.Policy.Mandatory} {
		for _, r := range rules {
			if err := check(r.Scope, r.Constraints, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func constraintFields(catalog schema.Catalog, constraints policy.Constraints) error {
	for _, value := range constraints.Values {
		if value.Field != "" && !catalog.HasOperation(value.Field) {
			return errors.New("value constraint references an unknown GraphQL field")
		}
	}
	for _, object := range constraints.Objects {
		if object.Field != "" && !catalog.HasOperation(object.Field) {
			return errors.New("object constraint references an unknown GraphQL field")
		}
	}
	return nil
}
