package config_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/credential/adapters"
	"github.com/gfx-labs/pdp/pkg/policy"
)

type fixture struct {
	dir string
	doc map[string]any
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir(), doc: map[string]any{
		"version": config.Version, "revision": "loader-test",
		"transport": map[string]any{"unix_socket": "run/pdp.sock"},
		"policy":    map[string]any{"modules": []string{"authz.rego"}},
		"credentials": map[string]any{
			"credentials_directory": "secrets",
			"providers":             map[string]any{"provider": map[string]any{"script_file": "adapter.star"}},
			"bindings": map[string]any{"binding": map[string]any{
				"provider": "provider", "state_file": "state/oauth.json",
				"secrets": map[string]any{"token": map[string]any{"file": "secrets/not-present"}},
			}},
		},
	}}
	f.write(t, "authz.rego", "package pdp.authz\ndefault allow := false\n")
	f.write(t, "adapter.star", adapters.Static)
	return f
}

func (f *fixture) write(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *fixture) path(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(f.doc)
	if err != nil {
		t.Fatal(err)
	}
	return f.write(t, "config.json", string(data))
}

// yaml is the fixture's configuration in block style.
func (f *fixture) yaml() string {
	return `version: pdp.config/v3
revision: loader-test
transport:
  unix_socket: run/pdp.sock
policy:
  modules:
    - authz.rego
credentials:
  credentials_directory: secrets
  providers:
    provider:
      script_file: adapter.star
  bindings:
    binding:
      provider: provider
      state_file: state/oauth.json
      secrets:
        token:
          file: secrets/not-present
`
}

// This boundary proves file resolution, exact OPA data and literal strings survive
// the real loader rather than only the policy engine's in-memory configuration.
func TestLoadAuthoredPolicySnapshot(t *testing.T) {
	t.Run("without data and with inline adapter", func(t *testing.T) {
		f := newFixture(t)
		f.doc["credentials"].(map[string]any)["providers"].(map[string]any)["provider"] = map[string]any{"script": adapters.Static}
		loaded, err := config.Load(context.Background(), f.path(t))
		if err != nil {
			t.Fatal(err)
		}
		defer loaded.Close()
		decision, err := loaded.Policy.Evaluate(context.Background(), policy.Input{
			Version: policy.InputVersion, Identity: policy.Identity{ID: "uid:123"}, Protocol: policy.ProtocolHTTP,
			Destination: policy.Destination{Scheme: "https", Host: "api.example.test", Port: 443}, HTTP: &policy.HTTPInput{Method: "GET", Path: "/"},
		})
		if err != nil || decision.Allow {
			t.Fatalf("policy without data did not evaluate its authored default: decision=%+v err=%v", decision, err)
		}
	})
	for _, notation := range []string{"9007199254740993", "9007199254740993.0", "9007199254740993e0"} {
		t.Run(notation, func(t *testing.T) {
			f := newFixture(t)
			f.doc["policy"] = map[string]any{
				"modules": []string{"authz.rego", "identity.rego"}, "data": []string{"data.json"},
			}
			f.doc["limits"] = map[string]any{"request_timeout": "3s"}
			f.doc["credentials"].(map[string]any)["limits"] = map[string]any{"timeout": "2s", "expiry_margin": 1000000000}
			f.write(t, "identity.rego", "package pdp.authz\napproved if input.identity.id == data.access.identity\n")
			f.write(t, "authz.rego", `package pdp.authz

default allow := false
allow if {
    approved
    input.http.body.counter == data.access.counter
    input.http.body.options == data.access.options
}
reasons := []
matched_rules := ["exact-data"] if allow
matched_rules := [] if not allow
`)
			f.write(t, "data.json", `{"access":{"identity":"uid:123","counter":`+notation+`,"options":{"timeout":"5s","max_age":"1m"}}}`)
			loaded, err := config.Load(context.Background(), f.path(t))
			if err != nil {
				t.Fatal(err)
			}
			defer loaded.Close()
			if loaded.Config.Limits.RequestTimeout != 3*time.Second || loaded.Config.Credentials.Limits.Timeout != 2*time.Second || loaded.Config.Credentials.Limits.ExpiryMargin != time.Second {
				t.Fatal("typed duration limits were not decoded")
			}
			if loaded.Config.Transport.UnixSocket != filepath.Join(f.dir, "run/pdp.sock") || loaded.Config.Credentials.CredentialsDirectory != filepath.Join(f.dir, "secrets") {
				t.Fatal("runtime paths were not relative to the config file")
			}
			binding := loaded.Config.Credentials.Bindings["binding"]
			if binding.Secrets["token"].File != filepath.Join(f.dir, "secrets/not-present") || binding.StateFile != filepath.Join(f.dir, "state/oauth.json") {
				t.Fatal("credential paths were not resolved without reading secrets or state")
			}
			provider := loaded.Config.Credentials.Providers["provider"]
			if provider.Script != adapters.Static || provider.ScriptFile != "" {
				t.Fatal("external adapter was not frozen into the snapshot")
			}
			input := policy.Input{
				Version: policy.InputVersion, Identity: policy.Identity{ID: "uid:123", AuthMethod: "unix"}, Protocol: policy.ProtocolHTTP, Binding: "binding",
				Destination: policy.Destination{Scheme: "https", Host: "api.example.test", Port: 443},
				HTTP:        &policy.HTTPInput{Method: "POST", Path: "/", Body: map[string]any{"counter": json.Number(notation), "options": map[string]any{"timeout": "5s", "max_age": "1m"}}},
			}
			decision, err := loaded.Policy.Evaluate(context.Background(), input)
			if err != nil || !decision.Allow || len(decision.MatchedRules) != 1 || decision.MatchedRules[0] != "exact-data" {
				t.Fatalf("authored files did not authorize exact data: decision=%+v err=%v", decision, err)
			}
			input.HTTP.Body.(map[string]any)["counter"] = json.Number("9007199254740992")
			decision, err = loaded.Policy.Evaluate(context.Background(), input)
			if err != nil || decision.Allow {
				t.Fatalf("data rounded to adjacent number: decision=%+v err=%v", decision, err)
			}
			f.write(t, "authz.rego", "invalid replacement")
			if next, err := config.Load(context.Background(), f.path(t)); err == nil {
				next.Close()
				t.Fatal("invalid replacement policy loaded")
			}
			input.HTTP.Body.(map[string]any)["counter"] = json.Number(notation)
			decision, err = loaded.Policy.Evaluate(context.Background(), input)
			if err != nil || !decision.Allow {
				t.Fatalf("failed reload changed existing policy snapshot: decision=%+v err=%v", decision, err)
			}
		})
	}
}

func TestLoadRejectsLegacyAndMalformedConfiguration(t *testing.T) {
	for _, key := range []string{"grants", "mode", "custom_modules", "operations", "denies", "mandatory", "relationships"} {
		t.Run("policy/"+key, func(t *testing.T) {
			f := newFixture(t)
			f.doc["policy"].(map[string]any)[key] = []any{}
			assertRejected(t, f.path(t))
		})
	}
	for _, key := range []string{"identities", "principal_tasks", "grants", "mode", "custom_modules", "routes"} {
		t.Run(key, func(t *testing.T) {
			f := newFixture(t)
			f.doc[key] = map[string]any{}
			assertRejected(t, f.path(t))
		})
	}
	t.Run("spiffe/principals", func(t *testing.T) {
		f := newFixture(t)
		f.doc["transport"].(map[string]any)["spiffe"] = map[string]any{
			"address": "127.0.0.1:8443", "workload_api": "unix:///missing-agent.sock", "principals": map[string]string{},
		}
		assertRejected(t, f.path(t))
	})
	for name, contents := range map[string]string{
		"duplicate":       `{"version":"pdp.config/v3","version":"pdp.config/v3"}`,
		"trailing":        `{"version":"pdp.config/v3"} {}`,
		"array":           `[]`,
		"null":            `null`,
		"empty":           "# only a comment\n",
		"nested-dupes":    `{"transport":{"unix_socket":"one","unix_socket":"two"}}`,
		"invalid-utf8":    "{\"revision\":\"\xff\"}",
		"yaml-duplicate":  "revision: one\nrevision: two\n",
		"yaml-documents":  "revision: one\n---\nrevision: two\n",
		"yaml-unknown":    "version: pdp.config/v3\nrevision: yaml\nroutes: []\n",
		"yaml-not-number": "limits:\n  max_concurrent: .inf\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			assertRejected(t, f.write(t, "config.json", contents))
		})
	}
	// An alias or merge key applies one written value in several places, and a
	// tag changes its type. In a file that wires credentials to hosts, what is
	// written must be what is applied. Each addition is otherwise valid.
	for name, addition := range map[string]string{
		"anchor":    "limits: &shared {max_concurrent: 4}\n",
		"merge-key": "limits:\n  <<: {max_concurrent: 4}\n",
		"tag":       "limits:\n  max_concurrent: !!int 4\n",
	} {
		t.Run("yaml-"+name, func(t *testing.T) {
			f := newFixture(t)
			assertRejected(t, f.write(t, "pdp.yaml", f.yaml()+addition))
		})
	}
}

// A YAML file is the same configuration as its JSON form: block style,
// comments and duration strings load, and paths still resolve from the file.
// The policy data file it names may be YAML too.
func TestLoadYAMLConfiguration(t *testing.T) {
	f := newFixture(t)
	f.write(t, "authz.rego", "package pdp.authz\n\nimport rego.v1\n\ndefault allow := false\n\nallow if input.identity.id in data.run_grants.readers\n")
	f.write(t, "grants.yaml", "# who may read\nrun_grants:\n  readers:\n    - uid:123\n")
	document := strings.Replace(f.yaml(), "    - authz.rego\n", "    - authz.rego\n  data:\n    - grants.yaml\n", 1)
	path := f.write(t, "pdp.yaml", "# administrator notes\n"+document+"limits:\n  request_timeout: 7s\n  max_concurrent: 3\n")
	loaded, err := config.Load(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	c := loaded.Config
	if c.Revision != "loader-test" || c.Limits.RequestTimeout != 7*time.Second || c.Limits.MaxConcurrent != 3 || c.Transport.UnixSocket != filepath.Join(f.dir, "run/pdp.sock") {
		t.Fatalf("YAML configuration loaded as %+v", c)
	}
	for id, want := range map[string]bool{"uid:123": true, "uid:999": false} {
		decision, err := loaded.Policy.Evaluate(context.Background(), policy.Input{
			Version: policy.InputVersion, Identity: policy.Identity{ID: id}, Protocol: policy.ProtocolHTTP,
			Destination: policy.Destination{Scheme: "https", Host: "api.example.test", Port: 443}, HTTP: &policy.HTTPInput{Method: "GET", Path: "/"},
		})
		if err != nil || decision.Allow != want {
			t.Fatalf("policy reading YAML data decided %s wrongly: decision=%+v err=%v", id, decision, err)
		}
	}
}

func TestLoadDependencyValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *fixture)
	}{
		{"no modules", func(t *testing.T, f *fixture) { f.doc["policy"] = map[string]any{} }},
		{"old config version", func(t *testing.T, f *fixture) { f.doc["version"] = "pdp.config/v2" }},
		{"missing module", func(t *testing.T, f *fixture) {
			f.doc["policy"] = map[string]any{"modules": []string{"missing.rego"}}
		}},
		{"empty module path", func(t *testing.T, f *fixture) {
			f.doc["policy"] = map[string]any{"modules": []string{""}}
		}},
		{"non Rego module", func(t *testing.T, f *fixture) {
			f.doc["policy"] = map[string]any{"modules": []string{"adapter.star"}}
		}},
		{"duplicate module", func(t *testing.T, f *fixture) {
			f.doc["policy"] = map[string]any{"modules": []string{"authz.rego", "./authz.rego"}}
		}},
		{"unreadable module", func(t *testing.T, f *fixture) {
			if err := os.Mkdir(filepath.Join(f.dir, "directory.rego"), 0700); err != nil {
				t.Fatal(err)
			}
			f.doc["policy"] = map[string]any{"modules": []string{"directory.rego"}}
		}},
		{"oversized module", func(t *testing.T, f *fixture) {
			f.write(t, "authz.rego", strings.Repeat(" ", config.MaxPolicyBytes+1))
		}},
		{"missing data", func(t *testing.T, f *fixture) {
			f.doc["policy"].(map[string]any)["data"] = []string{"missing.json"}
		}},
		{"multiple data files", func(t *testing.T, f *fixture) {
			f.doc["policy"].(map[string]any)["data"] = []string{"one.json", "two.json"}
		}},
		{"empty data path", func(t *testing.T, f *fixture) {
			f.doc["policy"].(map[string]any)["data"] = []string{""}
		}},
		{"both adapter sources", func(t *testing.T, f *fixture) {
			f.doc["credentials"].(map[string]any)["providers"].(map[string]any)["provider"].(map[string]any)["script"] = adapters.Static
		}},
		{"no adapter source", func(t *testing.T, f *fixture) {
			f.doc["credentials"].(map[string]any)["providers"].(map[string]any)["provider"] = map[string]any{}
		}},
		{"missing adapter", func(t *testing.T, f *fixture) {
			f.doc["credentials"].(map[string]any)["providers"].(map[string]any)["provider"] = map[string]any{"script_file": "missing.star"}
		}},
		{"oversized adapter", func(t *testing.T, f *fixture) {
			f.write(t, "adapter.star", strings.Repeat(" ", config.MaxAdapterBytes+1))
		}},
		{"unknown upstream schema", func(t *testing.T, f *fixture) {
			f.doc["upstreams"] = []config.Upstream{{Host: "api.example.test", Binding: "binding", Schema: "missing"}}
		}},
		{"binding and bindings", func(t *testing.T, f *fixture) {
			f.doc["upstreams"] = []config.Upstream{{Host: "api.example.test", Binding: "binding", Bindings: []string{"binding"}}}
		}},
		{"unknown tls mode", func(t *testing.T, f *fixture) {
			f.doc["upstreams"] = []config.Upstream{{Host: "api.example.test", TLS: "passthrough"}}
		}},
		{"transparent https without interception", func(t *testing.T, f *fixture) {
			f.doc["transport"].(map[string]any)["transparent"] = map[string]any{"https": ":443"}
		}},
		{"dns forward without resolver", func(t *testing.T, f *fixture) {
			f.doc["transport"].(map[string]any)["transparent"] = map[string]any{"http": ":80"}
			f.doc["dns"] = map[string]any{"listen": ":53", "address": "10.16.0.1"}
		}},
		{"dns without transparent listener", func(t *testing.T, f *fixture) {
			f.doc["dns"] = map[string]any{"listen": ":53", "address": "10.16.0.1", "unlisted": "refuse"}
		}},
		{"invalid CA", func(t *testing.T, f *fixture) {
			f.write(t, "ca.pem", "not a certificate")
			f.doc["ca_file"] = "ca.pem"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.change(t, f)
			assertRejected(t, f.path(t))
		})
	}
	for name, contents := range map[string]string{
		"duplicate data":         `{"access":{"counter":1,"counter":2}}`,
		"escaped duplicate data": `{"access":{"counter":1,"\u0063ounter":2}}`,
		"non object data":        `[]`,
		"null data":              `null`,
		"YAML duplicate data":    "access:\n  counter: 1\n  counter: 2\n",
		"YAML alias data":        "access: &a {counter: 1}\nother: *a\n",
		"YAML documents data":    "access: {}\n---\naccess: {}\n",
		"trailing data":          `{} {}`,
		"oversized data":         strings.Repeat(" ", config.MaxPolicyBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.doc["policy"].(map[string]any)["data"] = []string{"data.json"}
			f.write(t, "data.json", contents)
			assertRejected(t, f.path(t))
		})
	}
}

func TestLoadRejectsMistypedDurations(t *testing.T) {
	for _, path := range []string{"request_timeout", "timeout", "expiry_margin"} {
		for _, value := range []string{`null`, `true`, `[]`, `{}`, `1.5`, `1e9`, `9223372036854775808`, `"not-duration"`} {
			t.Run(path+"/"+value, func(t *testing.T) {
				f := newFixture(t)
				if path == "request_timeout" {
					f.doc["limits"] = map[string]any{path: json.RawMessage(value)}
				} else {
					f.doc["credentials"].(map[string]any)["limits"] = map[string]any{path: json.RawMessage(value)}
				}
				assertRejected(t, f.path(t))
			})
		}
	}
}

func assertRejected(t *testing.T, path string) {
	t.Helper()
	loaded, err := config.Load(context.Background(), path)
	if err == nil {
		loaded.Close()
		t.Fatal("invalid configuration loaded")
	}
	if loaded != nil {
		loaded.Close()
		t.Fatal("failed load returned a prospective snapshot")
	}
}
