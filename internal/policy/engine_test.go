package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gfx-labs/pdp/internal/policy"
)

func scope() policy.Scope {
	return policy.Scope{Identities: []string{"uid:1000"}, Providers: []string{"github"}, Bindings: []string{"work"}}
}
func full() policy.Grant { return policy.Grant{ID: "direct", Scope: scope(), Mode: policy.Full} }
func request() policy.Input {
	return policy.Input{Version: policy.InputVersion, Identity: policy.Identity{ID: "uid:1000"}, Provider: "github", Binding: "work", HTTP: policy.HTTPInput{Method: "POST", Path: "/api"}, Operations: []policy.OperationInput{{ID: "getIssue"}}}
}
func engine(t *testing.T, c policy.Config) *policy.Engine {
	t.Helper()
	if c.Revision == "" {
		c.Revision = "test-r1"
	}
	e, err := policy.New(context.Background(), c)
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
	if d.Revision != e.Revision() {
		t.Fatalf("decision revision mismatch: %+v", d)
	}
	return d
}

// Owns the direct-grant security boundary: classification must be reviewed and
// transport verbs, identity drift and unknown operations cannot widen authority.
func TestDirectModesAndTrustedEnvelope(t *testing.T) {
	operations := []policy.Operation{
		{ID: "getIssue", Provider: "github", Classification: policy.ReadOperation, Reviewed: true},
		{ID: "editIssue", Provider: "github", Classification: policy.WriteOperation, Reviewed: true},
		{ID: "deleteIssue", Provider: "github", Classification: policy.DestructiveOperation, Reviewed: true},
		{ID: "adminIssue", Provider: "github", Classification: policy.AdminOperation, Reviewed: true},
		{ID: "unreviewed", Provider: "github", Classification: policy.ReadOperation},
		{ID: "pinned", Provider: "github", SchemaDigest: "sha256:reviewed", Classification: policy.ReadOperation, Reviewed: true},
	}
	for _, mode := range []policy.Mode{policy.Full, policy.Read, policy.ReadWrite} {
		t.Run(string(mode), func(t *testing.T) {
			g := full()
			g.Mode = mode
			e := engine(t, policy.Config{Grants: []policy.Grant{g}, Operations: operations})
			for _, op := range []string{"getIssue", "editIssue", "deleteIssue", "adminIssue", "unreviewed", "unknown", "pinned"} {
				in := request()
				in.Operations[0].ID = op
				in.HTTP.Method = "GET"
				want := mode == policy.Full || op == "getIssue" || (mode == policy.ReadWrite && op == "editIssue")
				decide(t, e, in, want)
			}
			in := request()
			in.SchemaDigest = "sha256:reviewed"
			in.Operations[0].ID = "pinned"
			decide(t, e, in, true)
		})
	}
	decide(t, engine(t, policy.Config{}), request(), false)
	e := engine(t, policy.Config{Grants: []policy.Grant{full()}})
	for _, mutate := range []func(*policy.Input){func(i *policy.Input) { i.Version = "v2" }, func(i *policy.Input) { i.Identity.ID = "uid:2" }, func(i *policy.Input) { i.Provider = "linear" }, func(i *policy.Input) { i.Binding = "other" }, func(i *policy.Input) { i.Operations = nil }} {
		in := request()
		mutate(&in)
		decide(t, e, in, false)
	}
}

func TestConjunctiveGrantsAndDenyOverrides(t *testing.T) {
	g := full()
	g.Constraints = policy.Constraints{Repositories: []string{"repo-a"}, Issues: []string{"issue-a"}}
	other := full()
	other.ID = "other"
	other.Constraints = policy.Constraints{Repositories: []string{"repo-b"}, Issues: []string{"issue-b"}}
	e := engine(t, policy.Config{Grants: []policy.Grant{g, other}})
	in := request()
	in.Operations[0].Resources = []policy.Resource{{Type: "repository", ID: "repo-a"}, {Type: "issue", ID: "issue-b"}}
	decide(t, e, in, false)
	in.Operations[0].Resources[1].ID = "issue-a"
	decide(t, e, in, true)
	if len(e.Diagnostics()) == 0 {
		t.Fatal("missing overlap diagnostic")
	}
	for _, ruleKind := range []string{"deny-resource", "deny-value", "deny-missing-sibling", "mandatory"} {
		t.Run(ruleKind, func(t *testing.T) {
			c := policy.Config{Grants: []policy.Grant{full()}}
			in := request()
			in.Operations[0].Resources = []policy.Resource{{Type: "repository", ID: "blocked"}, {Type: "repository", ID: "allowed"}}
			in.HTTP.Query = map[string][]string{"repo": {"allowed", "blocked"}}
			switch ruleKind {
			case "deny-resource":
				c.Denies = []policy.Rule{{ID: "blocked", Constraints: policy.Constraints{Repositories: []string{"blocked"}}}}
			case "deny-value":
				c.Denies = []policy.Rule{{ID: "blocked", Constraints: policy.Constraints{Values: []policy.ValueConstraint{{Source: "query", Path: []string{"repo"}, Values: []any{"blocked"}}}}}}
			case "deny-missing-sibling":
				in.HTTP.Body = map[string]any{"items": []any{map[string]any{"repo": "blocked"}, map[string]any{}}}
				c.Denies = []policy.Rule{{ID: "blocked", Constraints: policy.Constraints{Values: []policy.ValueConstraint{{Source: "body", Path: []string{"items", "*", "repo"}, Values: []any{"blocked"}}}}}}
			case "mandatory":
				c.Mandatory = []policy.Rule{{ID: "allowed-only", Constraints: policy.Constraints{Repositories: []string{"allowed"}}}}
			}
			d := decide(t, engine(t, c), in, false)
			if len(d.DeniedBy) == 0 || len(d.MatchedGrants) == 0 {
				t.Fatalf("missing override explanation: %+v", d)
			}
		})
	}
}

func TestJSONNumericValueSemantics(t *testing.T) {
	denied := []any{json.Number("1"), json.Number("0"), json.Number("9007199254740992"), json.Number("1e10000")}
	constraint := policy.ValueConstraint{Source: "body", Path: []string{"value"}, Values: denied}
	e := engine(t, policy.Config{Grants: []policy.Grant{full()}, Denies: []policy.Rule{{ID: "number-deny", Constraints: policy.Constraints{Values: []policy.ValueConstraint{constraint}}}}})
	for _, text := range []string{"1", "1.0", "1e0", "10e-1", "0", "-0.0e1000", "9007199254740992.0", "10e9999"} {
		in := request()
		in.HTTP.Body = map[string]any{"value": json.Number(text)}
		decide(t, e, in, false)
	}
	for _, text := range []string{"2", "9007199254740993", "1e9999"} {
		in := request()
		in.HTTP.Body = map[string]any{"value": json.Number(text)}
		decide(t, e, in, true)
	}
	g := full()
	g.Constraints.Values = []policy.ValueConstraint{{Source: "body", Path: []string{"value"}, Values: []any{map[string]any{"id": json.Number("1")}}}}
	in := request()
	in.HTTP.Body = map[string]any{"value": map[string]any{"id": json.Number("1e0")}}
	decide(t, engine(t, policy.Config{Grants: []policy.Grant{g}}), in, true)
}

func TestGraphQLResourceInheritanceIsOccurrenceScoped(t *testing.T) {
	g := full()
	g.Constraints.Issues = []string{"allowed"}
	root := policy.Operation{ID: "Query.issue", Provider: "github", Classification: policy.ReadOperation, Reviewed: true, Resources: []policy.ResourceSelector{{Type: "issue", Source: "graphql", Path: []string{"id"}}}}
	child := policy.Operation{ID: "Issue.related", Provider: "github", Classification: policy.ReadOperation, Reviewed: true, Resources: []policy.ResourceSelector{{Type: "issue", Source: "graphql", Path: []string{"id"}}}}
	e := engine(t, policy.Config{Operations: []policy.Operation{root, child}, Grants: []policy.Grant{g}})
	in := request()
	in.Operations = nil
	in.GraphQL = []policy.FieldOccurrence{
		{Coordinate: "Query.issue", Path: []string{"a"}, Arguments: map[string]any{"id": "allowed"}},
		{Coordinate: "Issue.title", Path: []string{"a", "title"}, Arguments: map[string]any{}},
	}
	decide(t, e, in, true)
	// A root occurrence cannot lend its authorized issue to an unrelated alias.
	in.GraphQL = append(in.GraphQL, policy.FieldOccurrence{Coordinate: "Issue.title", Path: []string{"b", "title"}, Arguments: map[string]any{}})
	decide(t, e, in, false)
	in.GraphQL = append(in.GraphQL[:2], policy.FieldOccurrence{Coordinate: "Query.issue", Path: []string{"b"}, Arguments: map[string]any{"id": "blocked"}}, policy.FieldOccurrence{Coordinate: "Issue.title", Path: []string{"b", "title"}, Arguments: map[string]any{}})
	decide(t, e, in, false)
	// A child introducing another resource cannot erase its inherited context.
	in.GraphQL = append(in.GraphQL[:2], policy.FieldOccurrence{Coordinate: "Issue.related", Path: []string{"a", "related"}, Arguments: map[string]any{"id": "blocked"}})
	decide(t, e, in, false)
}

// Distinct occurrences must not merge arguments or inherit one matching alias.
func TestGraphQLRepeatedOccurrencesAndCollectionConstraints(t *testing.T) {
	g := full()
	g.Constraints.Values = []policy.ValueConstraint{{Source: "graphql", Field: "Query.issue", Path: []string{"id"}, Values: []any{"allowed"}}}
	e := engine(t, policy.Config{Grants: []policy.Grant{g}})
	in := request()
	in.Operations = nil
	in.GraphQL = []policy.FieldOccurrence{{Coordinate: "Query.issue", Path: []string{"a"}, Arguments: map[string]any{"id": "allowed"}}, {Coordinate: "Query.issue", Path: []string{"b"}, Arguments: map[string]any{"id": "blocked"}}}
	decide(t, e, in, false)
	in.GraphQL[1].Arguments["id"] = "allowed"
	d := decide(t, e, in, true)
	if len(d.Operations) != 2 {
		t.Fatal("field occurrences were collapsed")
	}
	g.Constraints.Values = []policy.ValueConstraint{{Source: "body", Path: []string{"items", "*", "repo"}, Values: []any{"allowed"}}}
	e = engine(t, policy.Config{Grants: []policy.Grant{g}})
	in = request()
	in.HTTP.Body = map[string]any{"items": []any{map[string]any{"repo": "allowed"}, map[string]any{}}}
	decide(t, e, in, false)
	in.HTTP.Body = map[string]any{"items": []any{map[string]any{"repo": "allowed"}, map[string]any{"repo": "allowed"}}}
	decide(t, e, in, true)
}

func TestRelationshipScopeExpiryAndTaskSelection(t *testing.T) {
	now := time.Now().UTC()
	g := full()
	g.Constraints.Relationship = &policy.RelationshipRequirement{Permission: "edit", ResourceTypes: []string{"issue"}}
	s := &policy.RelationshipSnapshot{Revision: "graph-1", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxAge: 2 * time.Minute, IdentityTasks: []policy.IdentityTask{{Identity: "uid:1000", Task: "task-a", ExpiresAt: now.Add(time.Hour)}}, TaskResources: []policy.TaskResource{{Task: "task-a", Resource: policy.Resource{Type: "issue", ID: "issue-a"}, Permission: "edit", ExpiresAt: now.Add(time.Hour)}}}
	in := request()
	in.Identity.TaskID = "task-a"
	in.Operations[0].Resources = []policy.Resource{{Type: "issue", ID: "issue-a"}}
	decide(t, engine(t, policy.Config{Grants: []policy.Grant{g}}), in, false)
	for _, test := range []struct {
		name   string
		mutate func(*policy.RelationshipSnapshot, *policy.Input)
		want   bool
	}{
		{"valid", func(*policy.RelationshipSnapshot, *policy.Input) {}, true},
		{"wrong-task", func(_ *policy.RelationshipSnapshot, i *policy.Input) { i.Identity.TaskID = "task-b" }, false},
		{"missing-task", func(_ *policy.RelationshipSnapshot, i *policy.Input) { i.Identity.TaskID = "" }, false},
		{"stale", func(s *policy.RelationshipSnapshot, _ *policy.Input) { s.MaxAge = time.Second }, false},
		{"expired-snapshot", func(s *policy.RelationshipSnapshot, _ *policy.Input) { s.ExpiresAt = now.Add(-time.Second) }, false},
		{"expired-membership", func(s *policy.RelationshipSnapshot, _ *policy.Input) {
			s.IdentityTasks[0].ExpiresAt = now.Add(-time.Second)
		}, false},
		{"expired-resource", func(s *policy.RelationshipSnapshot, _ *policy.Input) {
			s.TaskResources[0].ExpiresAt = now.Add(-time.Second)
		}, false},
		{"wrong-permission", func(s *policy.RelationshipSnapshot, _ *policy.Input) { s.TaskResources[0].Permission = "read" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, _ := json.Marshal(s)
			var copy policy.RelationshipSnapshot
			_ = json.Unmarshal(b, &copy)
			input := in
			test.mutate(&copy, &input)
			decide(t, engine(t, policy.Config{Grants: []policy.Grant{g}, Relationships: &copy}), input, test.want)
		})
	}
	// Even an expired graph must not impose a relationship on an unrelated grant.
	s.ExpiresAt = now.Add(-time.Second)
	direct := full()
	direct.ID = "unrelated-direct"
	decide(t, engine(t, policy.Config{Grants: []policy.Grant{g, direct}, Relationships: s}), in, true)
}

func TestNoPositiveDecisionCacheAndFrozenRevision(t *testing.T) {
	expires := time.Now().Add(time.Second)
	g := full()
	g.Constraints.Relationship = &policy.RelationshipRequirement{Permission: "read"}
	c := policy.Config{Revision: "revision-a", Grants: []policy.Grant{g}, Relationships: &policy.RelationshipSnapshot{Revision: "graph-a", IssuedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Hour), MaxAge: time.Hour, IdentityTasks: []policy.IdentityTask{{Identity: "uid:1000", Task: "task-a", ExpiresAt: expires}}, TaskResources: []policy.TaskResource{{Task: "task-a", Resource: policy.Resource{Type: "issue", ID: "1"}, Permission: "read", ExpiresAt: time.Now().Add(time.Hour)}}}}
	e := engine(t, c)
	in := request()
	in.Identity.TaskID = "task-a"
	in.Operations[0].Resources = []policy.Resource{{Type: "issue", ID: "1"}}
	explanation := decide(t, e, in, true)
	if explanation.Identity.ID != in.Identity.ID || explanation.Binding != in.Binding || len(explanation.MatchedGrantDetails) != 1 {
		t.Fatalf("incomplete explanation: %+v", explanation)
	}
	explanation.MatchedGrantDetails[0].Constraints.Relationship.Permission = "admin"
	explanation.Operations[0].Resources[0].ID = "different"
	c.Grants[0].Scope.Identities[0] = "uid:attacker"
	c.Revision = "changed"
	c.Relationships.IdentityTasks[0].ExpiresAt = time.Now().Add(time.Hour)
	decide(t, e, in, true)
	<-time.After(time.Until(expires) + 10*time.Millisecond)
	decide(t, e, in, false)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				d, err := e.Evaluate(context.Background(), in)
				if err != nil || d.Allow || d.Revision != "revision-a" {
					t.Errorf("concurrent decision: %+v, %v", d, err)
				}
			}
		})
	}
	wg.Wait()
}

func TestCustomRegoCannotGrantOrBypassRestrictions(t *testing.T) {
	for _, test := range []struct {
		name, source string
		grants       []policy.Grant
		mandatory    []policy.Rule
		want         bool
	}{
		{"cannot-grant", "package pdp.custom\nimport rego.v1\nallow := true", nil, nil, false},
		{"can-constrain", "package pdp.custom\nimport rego.v1\ndeny contains \"blocked\" if { input.identity.id == \"uid:1000\" }", []policy.Grant{full()}, nil, false},
		{"cannot-bypass", "package pdp.custom\nimport rego.v1\nallow := true", []policy.Grant{full()}, []policy.Rule{{ID: "digest", Constraints: policy.Constraints{SchemaDigests: []string{"required"}}}}, false},
		{"empty-deny", "package pdp.custom\nimport rego.v1\ndeny contains \"other\" if { input.identity.id == \"someone-else\" }", []policy.Grant{full()}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := engine(t, policy.Config{Grants: test.grants, Mandatory: test.mandatory, CustomModules: map[string]string{"custom.rego": test.source}})
			decide(t, e, request(), test.want)
		})
	}
	for _, source := range []string{"package pdp.base\nallow := true", "package pdp.custom\ndeny := false", "package pdp.custom\nimport rego.v1\ndeny contains \"network\" if { http.send({\"method\":\"GET\",\"url\":\"http://127.0.0.1\"}) }"} {
		if _, err := policy.New(context.Background(), policy.Config{Revision: "r", CustomModules: map[string]string{"bad.rego": source}}); err == nil {
			t.Fatalf("accepted unsafe custom module %q", source)
		}
	}
	e := engine(t, policy.Config{Grants: []policy.Grant{full()}, CustomModules: map[string]string{"runtime.rego": "package pdp.custom\nimport rego.v1\ndeny contains \"bad number\" if { to_number(input.http.method) > 0 }"}})
	d, err := e.Evaluate(context.Background(), request())
	if err == nil || d.Allow || d.Revision != e.Revision() {
		t.Fatalf("custom runtime failure did not fail closed: %+v, %v", d, err)
	}
}

func TestResourceExtractionAndUnknownOperationDiagnostics(t *testing.T) {
	g := full()
	g.Mode = policy.Read
	g.Constraints.Issues = []string{"9007199254740993"}
	c := policy.Config{Operations: []policy.Operation{{ID: "getIssue", Provider: "github", Reviewed: true, Classification: policy.ReadOperation, Resources: []policy.ResourceSelector{{Type: "issue", Source: "body", Path: []string{"id"}}}}}, Grants: []policy.Grant{g}}
	e := engine(t, c)
	in := request()
	in.HTTP.Body = map[string]any{"id": json.Number("9007199254740993")}
	decide(t, e, in, true)
	in.HTTP.Body = map[string]any{"id": json.Number("9007199254740992")}
	decide(t, e, in, false)
	in.HTTP.Body = nil
	decide(t, e, in, false)
	numericConfig := c
	numericGrant := full()
	numericConfig.Grants = []policy.Grant{numericGrant}
	numericConfig.Denies = []policy.Rule{{ID: "one-is-blocked", Constraints: policy.Constraints{Issues: []string{"1"}}}}
	numericEngine := engine(t, numericConfig)
	for _, text := range []string{"1.0", "1e0", "1.5", "1e10000"} {
		in.HTTP.Body = map[string]any{"id": json.Number(text)}
		decide(t, numericEngine, in, false)
	}
	c.Grants[0].Scope.Operations = []string{"typo"}
	e = engine(t, c)
	found := false
	for _, d := range e.Diagnostics() {
		if d.Code == "unknown_operation_reference" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing unknown operation diagnostic")
	}
	c.CustomModules = map[string]string{"reference.rego": "package pdp.custom\nimport rego.v1\ndeny contains \"unknown\" if { input.graphql[_].coordinate == \"Query.typo\" }"}
	e = engine(t, c)
	found = false
	for _, d := range e.Diagnostics() {
		if d.Code == "unknown_operation_reference" && len(d.Rules) == 1 && d.Rules[0] == "reference.rego" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing custom policy unknown operation diagnostic")
	}
	c.Operations[0].ID = "untyped:http:GET"
	c.Revision = "reserved-namespace-check"
	if _, err := policy.New(context.Background(), c); err == nil {
		t.Fatal("accepted reviewed operation in schema-free namespace")
	}
}

func TestCheckedInPolicyExample(t *testing.T) {
	b, err := os.ReadFile("../../policies/direct.json")
	if err != nil {
		t.Fatal(err)
	}
	var c policy.Config
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	e := engine(t, c)
	in := request()
	in.Identity.ID = "uid:1000"
	in.Provider = "github"
	in.Binding = "github-work"
	in.Operations[0].ID = "unregistered"
	decide(t, e, in, true)
	b, err = os.ReadFile("../../policies/restrict.rego")
	if err != nil {
		t.Fatal(err)
	}
	c.CustomModules = map[string]string{"restrict.rego": string(b)}
	e = engine(t, c)
	in.HTTP.Query = map[string][]string{"dangerous": {"true"}}
	decide(t, e, in, false)
	b, err = os.ReadFile("../../policies/restricted.json")
	if err != nil {
		t.Fatal(err)
	}
	var restricted policy.Config
	if err = json.Unmarshal(b, &restricted); err != nil {
		t.Fatal(err)
	}
	e = engine(t, restricted)
	in = request()
	in.Binding = "github-work"
	in.SchemaDigest = "sha256:replace-with-reviewed-schema-digest"
	in.HTTP.PathParams = map[string]string{"owner": "gfx-labs", "repo": "pdp", "issue_number": "1"}
	decide(t, e, in, true)
	in.HTTP.PathParams["owner"] = "another-owner"
	decide(t, e, in, false)
	in.HTTP.PathParams["owner"] = "gfx-labs"
	in.HTTP.PathParams["issue_number"] = "2"
	decide(t, e, in, false)
}
