package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gfx-labs/pdp/pkg/auth"
	"github.com/gfx-labs/pdp/pkg/config"
	"github.com/gfx-labs/pdp/pkg/credential"
)

// Load real policy files through the administrator config boundary, then send
// schema-validated requests over Unix peer authentication and verified TLS.
func TestAuthoredLinearRestrictions(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.Method != "POST" || r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("Linear upstream identity or destination changed")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var envelope map[string]any
		if err = json.Unmarshal(body, &envelope); err != nil {
			t.Error("upstream body is not canonical JSON")
		}
		if _, ok := envelope["query"].(string); !ok {
			t.Error("upstream query missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"commentCreate":{"success":true},"issue":{"id":"APP-1"}}}`)
	}, true, Options{})
	schemaPath, err := filepath.Abs("../schema/testdata/linear.graphql")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile("testdata/linear.rego")
	if err != nil {
		t.Fatal(err)
	}
	policyData, err := json.Marshal(map[string]any{
		"peer_uid": os.Getuid(),
		"issue_fields": map[string]any{
			"APP-1": []string{"Issue.id", "Issue.identifier", "Issue.title", "Issue.description"},
			"APP-3": []string{"Issue.id"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{"token": []byte(testToken), "linear.rego": module, "data.json": policyData} {
		if err = os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{
		Version: config.Version, Revision: "linear-authored-v1", Transport: config.Transport{UnixSocket: h.socket, SocketMode: "0600"},
		Schemas:     map[string]config.Schema{"linear": {Protocol: "graphql", File: schemaPath}},
		Routes:      []config.Route{{Provider: "linear", Binding: "installation", UpstreamURL: h.endpoint + "/graphql", Schema: "linear"}},
		Credentials: credential.Config{Providers: map[string]credential.ProviderConfig{"linear": {Script: "def acquire(ctx):\n    return static(secret(\"token\"))\n"}}, Bindings: map[string]credential.BindingConfig{"installation": {Provider: "linear", Secrets: map[string]credential.SecretSource{"token": {File: "token"}}}}},
		Policy:      config.Policy{Modules: []string{"linear.rego"}, Data: []string{"data.json"}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(context.Background(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewSnapshot(SnapshotConfig{Version: loaded.Config.Revision, Authenticator: auth.NewUnix(), Policy: loaded.Policy, Credentials: loaded.Credentials, Routes: []Route{{Provider: "linear", Binding: "installation", UpstreamURL: h.endpoint + "/graphql", GraphQL: loaded.GraphQL["linear"]}}})
	if err != nil {
		loaded.Close()
		t.Fatal(err)
	}
	if err = h.g.Reload(snapshot); err != nil {
		loaded.Close()
		t.Fatal(err)
	}
	tests := []struct {
		name, query string
		variables   map[string]any
		status      int
	}{
		{"literal comment", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello"}) { success comment { id body } } }`, nil, 200},
		{"variable input", `mutation Add($input:CommentCreateInput!) { commentCreate(input:$input) { success } }`, map[string]any{"input": map[string]any{"issueId": "APP-1", "body": "variable"}}, 200},
		{"default input", `mutation Add($input:CommentCreateInput!={issueId:"APP-1",body:"default"}) { commentCreate(input:$input) { success } }`, nil, 200},
		{"foreign issue", `mutation { commentCreate(input:{issueId:"APP-2",body:"hello"}) { success } }`, nil, 403},
		{"project side effect", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello",projectId:"foreign-project"}) { success } }`, nil, 403},
		{"parent side effect", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello",parentId:"foreign-parent"}) { success } }`, nil, 403},
		{"impersonation side effect", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello",createAsUser:"administrator"}) { success } }`, nil, 403},
		{"slack side effect", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello",createOnSyncedSlackThread:true}) { success } }`, nil, 403},
		{"variable side effect", `mutation Add($input:CommentCreateInput!) { commentCreate(input:$input) { success } }`, map[string]any{"input": map[string]any{"issueId": "APP-1", "body": "hello", "projectId": "foreign"}}, 403},
		{"missing body", `mutation { commentCreate(input:{issueId:"APP-1"}) { success } }`, nil, 403},
		{"missing issue", `mutation { commentCreate(input:{body:"hello"}) { success } }`, nil, 403},
		{"null body", `mutation { commentCreate(input:{issueId:"APP-1",body:null}) { success } }`, nil, 403},
		{"empty body", `mutation { commentCreate(input:{issueId:"APP-1",body:""}) { success } }`, nil, 403},
		{"repeated allowed aliases", `{ first:issue(id:"APP-1") { id } second:issue(id:"APP-1") { title } }`, nil, 200},
		{"mixed issue aliases", `{ first:issue(id:"APP-1") { id } second:issue(id:"APP-2") { title } }`, nil, 403},
		{"scoped descendants allowed", `{ first:issue(id:"APP-1") { description } second:issue(id:"APP-3") { id } }`, nil, 200},
		{"scoped descendants denied", `{ first:issue(id:"APP-1") { description } second:issue(id:"APP-3") { description } }`, nil, 403},
		{"same alias distinct occurrences", `{ same:issue(id:"APP-1") { id } same:issue(id:"APP-2") { id } }`, nil, 400},
		{"fragment and variable default", `query Read($id:String!="APP-1") { selected:issue(id:$id) { ...IssueFields } } fragment IssueFields on Issue { id title }`, nil, 200},
		{"fragment ancestor denied", `{ first:issue(id:"APP-1") { ...Details } second:issue(id:"APP-3") { ...Details } } fragment Details on Issue { description }`, nil, 403},
		{"false forbidden branch", `{ allowed:issue(id:"APP-1") { id } forbidden:issue(id:"APP-2") @include(if:false) { ...IssueFields } } fragment IssueFields on Issue { id }`, nil, 403},
		{"skipped forbidden descendant", `{ allowed:issue(id:"APP-1") { id } restricted:issue(id:"APP-3") { description @skip(if:true) } }`, nil, 403},
		{"unreviewed output", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello"}) { success lastSyncId } }`, nil, 403},
		{"aliased forbidden output", `{ issue(id:"APP-1") { title:url } }`, nil, 403},
		{"unknown destructive mutation", `mutation { issueDelete(id:"APP-1") { success } }`, nil, 400},
		{"unsupported custom scalar", `mutation { commentCreate(input:{issueId:"APP-1",body:"hello",bodyData:"opaque"}) { success } }`, nil, 400},
	}
	var accepted int64
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := map[string]any{"query": test.query}
			if test.variables != nil {
				envelope["variables"] = test.variables
			}
			body, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			beforeCalls := calls.Load()
			beforeStats := h.g.Metrics().Credentials
			status, _, response := h.request(t, "POST", "/upstreams/linear/graphql", string(body), http.Header{})
			if status != test.status {
				t.Fatalf("status=%d want=%d body=%s", status, test.status, response)
			}
			if strings.Contains(response, testToken) {
				t.Fatal("response contains provider credential")
			}
			if status == 200 {
				accepted++
				if calls.Load() != beforeCalls+1 {
					t.Fatal("allowed request was not forwarded once")
				}
			} else {
				if calls.Load() != beforeCalls {
					t.Fatal("denied request reached upstream")
				}
				afterStats := h.g.Metrics().Credentials
				if afterStats.Hits != beforeStats.Hits || afterStats.Misses != beforeStats.Misses || afterStats.Acquisitions != beforeStats.Acquisitions {
					t.Fatal("denied request acquired or looked up credentials")
				}
			}
		})
	}
	stats := h.g.Metrics().Credentials
	if calls.Load() != accepted || stats.Acquisitions != 1 || stats.Hits != uint64(accepted-1) {
		t.Fatalf("forward/cache accounting mismatch: accepted=%d calls=%d stats=%+v", accepted, calls.Load(), stats)
	}
}
