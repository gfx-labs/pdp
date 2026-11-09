package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gfx-labs/pdp/pkg/policy"
)

// This boundary owns configuration precision and preventing a removed schema
// from silently disabling a typed deny. Policy and schema tests cannot prove
// that their trusted inputs survive the administrator YAML/JSON loader.
func TestLoadSnapshotSecurity(t *testing.T) {
	path, err := filepath.Abs("../../examples/github-read.yaml")
	if err != nil {
		t.Fatal(err)
	}
	original, err := Load(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	base := original.Config
	for name, spec := range base.Schemas {
		spec.File = resolve(filepath.Dir(path), spec.File)
		base.Schemas[name] = spec
	}
	write := func(c Config) string {
		t.Helper()
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "pdp.json")
		if err = os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	t.Run("exact large constraint number", func(t *testing.T) {
		for _, notation := range []string{"9007199254740993", "9007199254740993.0", "9007199254740993e0"} {
			for _, format := range []string{"json", "yaml"} {
				t.Run(notation+"/"+format, func(t *testing.T) {
					c := base
					c.Policy.Grants = []policy.Grant{{ID: "numeric", Mode: policy.Read, Scope: policy.Scope{Identities: []string{"worker"}, Providers: []string{"github"}, Bindings: []string{"github-repo"}}, Constraints: policy.Constraints{Values: []policy.ValueConstraint{{Source: "body", Path: []string{"counter"}, Values: []any{json.Number(notation)}}}}}}
					file := write(c)
					if format == "yaml" {
						data, err := os.ReadFile(file)
						if err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(file, append([]byte("# YAML input\n"), data...), 0600); err != nil {
							t.Fatal(err)
						}
					}
					loaded, err := Load(context.Background(), file)
					if err != nil {
						t.Fatal(err)
					}
					defer loaded.Close()
					for _, value := range []string{notation, "9007199254740992"} {
						input := policy.Input{Version: policy.InputVersion, Identity: policy.Identity{ID: "worker"}, Provider: "github", Binding: "github-repo", SchemaDigest: loaded.Catalogs["github"].Digest, HTTP: policy.HTTPInput{PathParams: map[string]string{"owner": "owner", "repo": "repo"}, Body: map[string]any{"counter": json.Number(value)}}, Operations: []policy.OperationInput{{ID: "repos/get"}}}
						decision, err := loaded.Policy.Evaluate(context.Background(), input)
						if err != nil {
							t.Fatal(err)
						}
						if decision.Allow != (value == notation) {
							t.Errorf("constraint number %s incorrectly allowed=%t", value, decision.Allow)
						}
					}
				})
			}
		}
	})
	t.Run("duration-looking policy values remain literal", func(t *testing.T) {
		c := base
		value := map[string]any{"timeout": "5s", "max_age": "1m"}
		c.Policy.Grants = []policy.Grant{{ID: "literal", Mode: policy.Read, Scope: policy.Scope{Identities: []string{"worker"}, Providers: []string{"github"}, Bindings: []string{"github-repo"}}, Constraints: policy.Constraints{Values: []policy.ValueConstraint{{Source: "body", Path: []string{"options"}, Values: []any{value}}}}}}
		loaded, err := Load(context.Background(), write(c))
		if err != nil {
			t.Fatal(err)
		}
		defer loaded.Close()
		input := policy.Input{Version: policy.InputVersion, Identity: policy.Identity{ID: "worker"}, Provider: "github", Binding: "github-repo", SchemaDigest: loaded.Catalogs["github"].Digest, HTTP: policy.HTTPInput{PathParams: map[string]string{"owner": "owner", "repo": "repo"}, Body: map[string]any{"options": value}}, Operations: []policy.OperationInput{{ID: "repos/get"}}}
		decision, err := loaded.Policy.Evaluate(context.Background(), input)
		if err != nil || !decision.Allow {
			t.Fatalf("literal duration map changed: allow=%t err=%v", decision.Allow, err)
		}
	})
	t.Run("removed schema cannot disable deny", func(t *testing.T) {
		c := base
		c.Schemas = nil
		c.Policy.Operations = nil
		c.Routes = append([]Route(nil), base.Routes...)
		c.Routes[0].Schema = ""
		c.Policy.Grants = []policy.Grant{{ID: "full", Mode: policy.Full, Scope: policy.Scope{Identities: []string{"worker"}, Providers: []string{"github"}, Bindings: []string{"github-repo"}}}}
		c.Policy.Denies = []policy.Rule{{ID: "deny-comment", Scope: policy.Scope{Providers: []string{"github"}, Operations: []string{"issues/create-comment"}}}}
		if loaded, err := Load(context.Background(), write(c)); err == nil {
			loaded.Close()
			t.Fatal("typed deny accepted without its schema")
		}
	})
	t.Run("same operation ID does not approve schema drift", func(t *testing.T) {
		c := base
		c.Policy.Operations = nil
		raw, err := os.ReadFile(base.Schemas["github"].File)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err = json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		paths := doc["paths"].(map[string]any)
		repository := paths["/repos/{owner}/{repo}"].(map[string]any)
		repository["post"] = repository["get"]
		delete(repository, "get")
		raw, err = json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		spec := filepath.Join(t.TempDir(), "changed.json")
		if err = os.WriteFile(spec, raw, 0600); err != nil {
			t.Fatal(err)
		}
		c.Schemas = map[string]Schema{"github": {Protocol: "rest", File: spec}}
		if loaded, err := Load(context.Background(), write(c)); err == nil {
			loaded.Close()
			t.Fatal("changed read operation automatically approved by ID")
		}
	})
	t.Run("unknown operation cannot silently miss", func(t *testing.T) {
		c := base
		c.Policy.Denies = []policy.Rule{{ID: "deny-typo", Scope: policy.Scope{Providers: []string{"github"}, Operations: []string{"issues/misspelled"}}}}
		if loaded, err := Load(context.Background(), write(c)); err == nil {
			loaded.Close()
			t.Fatal("unknown operation reference accepted")
		}
	})
}
