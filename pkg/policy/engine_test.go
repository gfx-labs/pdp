package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/pkg/policy"
)

func request() policy.Input {
	return policy.Input{
		Version: policy.InputVersion, Identity: policy.Identity{ID: "worker"},
		Provider: "github", Binding: "installation", SchemaDigest: "sha256:reviewed",
		HTTP:       policy.HTTPInput{Method: "POST", Path: "/api"},
		Operations: []policy.OperationInput{{ID: "issues/get"}},
	}
}

func engine(t *testing.T, source string, data map[string]any) *policy.Engine {
	t.Helper()
	e, err := policy.New(context.Background(), policy.Config{
		Revision: "test-r1", Modules: map[string]string{"authz.rego": "package pdp.authz\n" + source}, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func decide(t *testing.T, e *policy.Engine, in policy.Input, want bool) policy.Decision {
	t.Helper()
	d, err := e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow != want {
		t.Fatalf("allow=%v want=%v: %+v", d.Allow, want, d)
	}
	return d
}

// Authored source, not Go-side operation classifications, owns permissions.
func TestAuthoredFullAndRestrictedPolicies(t *testing.T) {
	full := engine(t, `
		default allow := false
		allow if {
			input.identity.id == "worker"
			input.provider == "github"
			input.binding == "installation"
		}
		matched_rules contains "full-access" if allow
	`, nil)
	in := request()
	in.Operations[0].ID = "arbitrary/destructive-operation"
	d := decide(t, full, in, true)
	if !reflect.DeepEqual(d.MatchedRules, []string{"full-access"}) {
		t.Fatalf("missing authored rule explanation: %+v", d)
	}
	in.Identity.ID = "other"
	decide(t, full, in, false)
	decide(t, engine(t, "default allow := false", nil), request(), false)

	restricted := engine(t, `
		default allow := false
		allow if {
			input.identity.id == "worker"
			input.provider == "github"
			input.binding == "installation"
			input.schema_digest == "sha256:reviewed"
			every operation in input.operations {
				operation.id in {"issues/get", "issues/create-comment"}
			}
			input.http.path_params.owner == "team"
			input.http.path_params.repo == "project"
			not blocked
		}
		blocked if input.http.body.locked == true
		reasons contains "locked issue" if blocked
		matched_rules contains "repository-access" if allow
	`, nil)
	in = request()
	in.HTTP.PathParams = map[string]string{"owner": "team", "repo": "project"}
	decide(t, restricted, in, true)
	in.Operations = append(in.Operations, policy.OperationInput{ID: "issues/delete"})
	decide(t, restricted, in, false)
	in.Operations = in.Operations[:1]
	in.HTTP.PathParams["repo"] = "other"
	decide(t, restricted, in, false)
	in.HTTP.PathParams["repo"] = "project"
	in.HTTP.Body = map[string]any{"locked": true}
	d = decide(t, restricted, in, false)
	if !reflect.DeepEqual(d.Reasons, []string{"locked issue"}) {
		t.Fatalf("missing authored denial explanation: %+v", d)
	}
}

// Exact verified proof metadata reaches source, including a present Unix UID 0.
func TestVerifiedIdentityProofs(t *testing.T) {
	e := engine(t, `
		default allow := false
		allow if {
			input.identity.auth_method == "unix-peer"
			input.identity.uid == 0
		}
		allow if {
			input.identity.auth_method == "spiffe-mtls"
			input.identity.spiffe_id == "spiffe://example.test/worker"
		}
	`, nil)
	zero, other := uint32(0), uint32(1000)
	for _, tc := range []struct {
		name     string
		identity policy.Identity
		allow    bool
	}{
		{"uid-zero", policy.Identity{ID: "local-root", AuthMethod: "unix-peer", UID: &zero}, true},
		{"uid-other", policy.Identity{ID: "local-root", AuthMethod: "unix-peer", UID: &other}, false},
		{"uid-absent", policy.Identity{ID: "local-root", AuthMethod: "unix-peer"}, false},
		{"spiffe", policy.Identity{ID: "workload", AuthMethod: "spiffe-mtls", SPIFFEID: "spiffe://example.test/worker"}, true},
		{"spiffe-other", policy.Identity{ID: "workload", AuthMethod: "spiffe-mtls", SPIFFEID: "spiffe://example.test/other"}, false},
		{"proof-method", policy.Identity{ID: "workload", AuthMethod: "unix-peer", SPIFFEID: "spiffe://example.test/worker"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := request()
			in.Identity = tc.identity
			d := decide(t, e, in, tc.allow)
			if !reflect.DeepEqual(d.Identity, tc.identity) {
				t.Fatalf("identity was rewritten: got %+v want %+v", d.Identity, tc.identity)
			}
		})
	}
}

func TestGraphQLRepeatedOccurrences(t *testing.T) {
	e := engine(t, `
		default allow := false
		allow if {
			count(input.graphql) == 2
			every field in input.graphql {
				field.coordinate == "Query.issue"
				field.arguments.id == "APP-1"
			}
			input.graphql[0].response_path == ["first"]
			input.graphql[1].response_path == ["second"]
		}
	`, nil)
	in := request()
	in.Provider = "linear"
	in.Operations = []policy.OperationInput{{ID: "Query.issue", Resources: []policy.Resource{{Type: "issue", ID: "APP-1"}}}}
	in.GraphQL = []policy.FieldOccurrence{
		{Coordinate: "Query.issue", Path: []string{"first"}, ResponsePath: []string{"first"}, Alias: "first", Arguments: map[string]any{"id": "APP-1"}},
		{Coordinate: "Query.issue", Path: []string{"second"}, ResponsePath: []string{"second"}, Alias: "second", Arguments: map[string]any{"id": "APP-1"}},
	}
	d := decide(t, e, in, true)
	if len(d.Operations) != 2 || d.Operations[0].Path[0] != "first" || d.Operations[1].Path[0] != "second" || !reflect.DeepEqual(d.Operations[1].Resources, in.Operations[0].Resources) {
		t.Fatalf("occurrences collapsed or changed: %+v", d.Operations)
	}
	in.GraphQL[1].Arguments["id"] = "APP-2"
	decide(t, e, in, false)
	in.GraphQL[1].Arguments = map[string]any{}
	decide(t, e, in, false)
	in.GraphQL[1].Arguments["id"] = "APP-1"
	decide(t, e, in, true)
}

// Arbitrary administrator data is standard OPA data, with no Go permission DSL.
func TestArbitrarySourceAndExactJSONNumbers(t *testing.T) {
	e := engine(t, `
		default allow := false
		allow if {
			input.http.body.counter == data.business.counter
			input.http.normalized_query.limit == 1
			input.variables.options == data.business.options
			startswith(input.http.path, "/api")
			not input._pdp
		}
	`, map[string]any{"business": map[string]any{
		"counter": json.Number("9007199254740993"),
		"options": map[string]any{"threshold": json.Number("1.25"), "enabled": true},
	}})
	in := request()
	in.HTTP.Query = map[string][]string{"limit": {"1"}}
	in.HTTP.NormalizedQuery = map[string]any{"limit": json.Number("1e0")}
	in.Variables = map[string]any{"options": map[string]any{"threshold": json.Number("1.250"), "enabled": true}}
	for _, tc := range []struct {
		number string
		allow  bool
	}{
		{"9007199254740993", true}, {"9007199254740993.0", true}, {"9007199254740992", false}, {"9007199254740994", false},
	} {
		in.HTTP.Body = map[string]any{"counter": json.Number(tc.number)}
		decide(t, e, in, tc.allow)
	}
}

func TestInvalidResultsAndEvaluationErrorsFailClosed(t *testing.T) {
	for _, tc := range []struct{ name, source, errorText string }{
		{"missing-allow", `reasons contains "no decision"`, "policy allow"},
		{"undefined-allow", `allow if input.identity.id == "nobody"`, "policy allow"},
		{"nonboolean-allow", `allow := "true"`, "policy allow"},
		{"null-allow", `allow := null`, "policy allow"},
		{"invalid-reasons", "allow := true\nreasons := \"trusted\"", "policy reasons"},
		{"nonstring-reasons", "allow := true\nreasons contains 42", "policy reasons"},
		{"invalid-matched-rules", "allow := true\nmatched_rules contains {\"id\": \"rule\"}", "policy matched_rules"},
		{"builtin-error", "default allow := false\nallow if { to_number(input.http.path) > 0 }", "eval_builtin_error"},
		{"evaluation-conflict", "allow := true\nallow := false if input.identity.id == \"worker\"", "eval_conflict_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := engine(t, tc.source, nil).Evaluate(context.Background(), request())
			if d.Allow || err == nil || !strings.Contains(err.Error(), tc.errorText) {
				t.Fatalf("malformed result must deny: decision=%+v error=%v", d, err)
			}
		})
	}
}

func TestConfigValidationAndRestrictedCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config policy.Config
	}{
		{"revision", policy.Config{Modules: map[string]string{"authz.rego": "package pdp.authz\nallow := true"}}},
		{"no-module", policy.Config{Revision: "r1"}},
		{"empty-source", policy.Config{Revision: "r1", Modules: map[string]string{"authz.rego": " "}}},
		{"empty-name", policy.Config{Revision: "r1", Modules: map[string]string{"": "package pdp.authz\nallow := true"}}},
		{"namespace", policy.Config{Revision: "r1", Modules: map[string]string{"other.rego": "package other\nallow := true"}}},
		{"syntax", policy.Config{Revision: "r1", Modules: map[string]string{"authz.rego": "package pdp.authz\nallow if {"}}},
		{"shadow-contract", policy.Config{Revision: "r1", Modules: map[string]string{"authz.rego": "package pdp.authz\ndefault allow := false"}, Data: map[string]any{"pdp": map[string]any{"authz": map[string]any{"allow": true}}}}},
		{"shadow-parent", policy.Config{Revision: "r1", Modules: map[string]string{"authz.rego": "package pdp.authz\nallow := true"}, Data: map[string]any{"pdp": true}}},
		{"non-json-data", policy.Config{Revision: "r1", Modules: map[string]string{"authz.rego": "package pdp.authz\nallow := true"}, Data: map[string]any{"invalid": make(chan int)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := policy.New(context.Background(), tc.config); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for name, body := range map[string]string{
		"http":    `http.send({"method": "GET", "url": "http://127.0.0.1"})`,
		"dns":     `net.lookup_ip_addr("localhost")`,
		"runtime": `opa.runtime()`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := policy.New(context.Background(), policy.Config{Revision: "r1", Modules: map[string]string{
				"authz.rego": "package pdp.authz\nallow if { " + body + " }",
			}})
			if err == nil || !strings.Contains(err.Error(), "undefined function") {
				t.Fatalf("restricted builtin accepted: %v", err)
			}
		})
	}
}

func TestFrozenSnapshotConcurrentEvaluationAndCancellation(t *testing.T) {
	data := map[string]any{"approved": []any{"worker"}}
	modules := map[string]string{
		"authz.rego":   "package pdp.authz\ndefault allow := false\nallow if approved(input.identity.id)\nmatched_rules contains \"approved\" if allow",
		"helpers.rego": "package pdp.authz\napproved(identity) if identity in data.approved",
	}
	config := policy.Config{Revision: "before", Modules: modules, Data: data}
	e, err := policy.New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	config.Revision = "after"
	modules["authz.rego"] = "package pdp.authz\nallow := false"
	data["approved"].([]any)[0] = "other"
	const count = 24
	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() {
			in := request()
			want := i%2 == 0
			if !want {
				in.Identity.ID = "other"
			}
			d, err := e.Evaluate(context.Background(), in)
			if err != nil || d.Allow != want || d.Revision != "before" {
				t.Errorf("snapshot evaluation: allow=%v want=%v revision=%q err=%v", d.Allow, want, d.Revision, err)
			}
		})
	}
	wg.Wait()
	in := request()
	uid := uint32(1000)
	in.Identity.UID = &uid
	in.Operations[0].Resources = []policy.Resource{{Type: "issue", ID: "APP-1"}}
	d := decide(t, e, in, true)
	*d.Identity.UID = 7
	d.Operations[0].Resources[0].ID = "changed"
	d.MatchedRules[0] = "changed"
	if uid != 1000 || in.Operations[0].Resources[0].ID != "APP-1" {
		t.Fatal("decision aliases input")
	}
	d = decide(t, e, in, true)
	if !reflect.DeepEqual(d.MatchedRules, []string{"approved"}) {
		t.Fatal("decision mutation changed snapshot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err = e.Evaluate(ctx, in)
	if d.Allow || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled evaluation: %+v, %v", d, err)
	}
	if _, err := policy.New(ctx, policy.Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled construction: %v", err)
	}
}

func TestTrustedEnvelopeFailsClosed(t *testing.T) {
	e := engine(t, "allow := true", nil)
	for name, mutate := range map[string]func(*policy.Input){
		"version":             func(in *policy.Input) { in.Version = "v2" },
		"identity":            func(in *policy.Input) { in.Identity.ID = "" },
		"provider":            func(in *policy.Input) { in.Provider = "" },
		"binding":             func(in *policy.Input) { in.Binding = "" },
		"no-operations":       func(in *policy.Input) { in.Operations = nil },
		"operation-id":        func(in *policy.Input) { in.Operations[0].ID = "" },
		"graphql-coordinate":  func(in *policy.Input) { in.GraphQL = []policy.FieldOccurrence{{}} },
		"resource-id":         func(in *policy.Input) { in.Operations[0].Resources = []policy.Resource{{Type: "issue"}} },
		"query-normalization": func(in *policy.Input) { in.HTTP.Query = map[string][]string{"limit": {"1"}} },
	} {
		t.Run(name, func(t *testing.T) {
			in := request()
			mutate(&in)
			decide(t, e, in, false)
		})
	}
	in := request()
	in.HTTP.Body = make(chan int)
	if d, err := e.Evaluate(context.Background(), in); err == nil || d.Allow {
		t.Fatalf("non-JSON input accepted: %+v, %v", d, err)
	}
}

func TestTimeSensitivePolicyIsReevaluated(t *testing.T) {
	e := engine(t, `
		default allow := false
		allow if time.now_ns() < input.http.body.expires_at_ns
	`, nil)
	in := request()
	expires := time.Now().Add(time.Second)
	in.HTTP.Body = map[string]any{"expires_at_ns": expires.UnixNano()}
	decide(t, e, in, true)
	time.Sleep(time.Until(expires) + time.Millisecond)
	decide(t, e, in, false)
}
