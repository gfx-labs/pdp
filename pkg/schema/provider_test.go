package schema_test

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gfx-labs/pdp/pkg/schema"
)

// These requests are normalized locally. No provider requests are sent.
func TestPinnedProviderRequestSurfaces(t *testing.T) {
	githubBytes, err := os.ReadFile("testdata/github-rest.json")
	if err != nil {
		t.Fatal(err)
	}
	github, err := schema.CompileREST(githubBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, body, id string }{
		{"GET", "/repos/gfx-labs/pdp", "", "repos/get"},
		{"GET", "/repos/gfx-labs/pdp/issues/123", "", "issues/get"},
		{"GET", "/repos/gfx-labs/pdp/issues/123/comments?per_page=10&page=2", "", "issues/list-comments"},
		{"POST", "/repos/gfx-labs/pdp/issues/123/comments", `{"body":"Recorded schema normalization only"}`, "issues/create-comment"},
	} {
		req := httptest.NewRequest(tc.method, "https://api.github.com"+tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		normalized, err := github.Normalize(req)
		if err != nil || normalized.OperationID != tc.id {
			t.Fatalf("%s: %#v %v", tc.id, normalized, err)
		}
	}
	if err = github.Catalog().ValidateReferences([]string{"repos/get", "issues/get", "issues/list-comments", "issues/create-comment"}); err != nil {
		t.Fatal(err)
	}
	linearBytes, err := os.ReadFile("testdata/linear.graphql")
	if err != nil {
		t.Fatal(err)
	}
	linear, err := schema.CompileGraphQL(linearBytes)
	if err != nil {
		t.Fatal(err)
	}
	read, err := linear.Normalize(`query Get($id:String!){issue(id:$id){id identifier title description url}}`, "Get", map[string]any{"id": "APP-123"})
	if err != nil || len(read.Fields) != 6 || read.Fields[0].Coordinate != "Query.issue" {
		t.Fatalf("issue read: %#v %v", read, err)
	}
	write, err := linear.Normalize(`mutation Comment($first:CommentCreateInput!,$second:CommentCreateInput!){a:commentCreate(input:$first){success comment{id body issue{id}}} b:commentCreate(input:$second){success}}`, "Comment", map[string]any{"first": map[string]any{"issueId": "APP-123", "body": "one"}, "second": map[string]any{"issueId": "APP-456", "body": "two"}})
	if err != nil {
		t.Fatal(err)
	}
	comments := []schema.FieldOccurrence{}
	for _, f := range write.Fields {
		if f.Coordinate == "Mutation.commentCreate" {
			comments = append(comments, f)
		}
	}
	if len(comments) != 2 || comments[0].Arguments["input"].(map[string]any)["issueId"] != "APP-123" || comments[1].Arguments["input"].(map[string]any)["issueId"] != "APP-456" {
		t.Fatalf("distinct real-provider mutations merged: %#v", comments)
	}
	if _, err = linear.Normalize(`mutation($input:CommentCreateInput!){commentCreate(input:$input){success}}`, "", map[string]any{"input": map[string]any{"issueId": "APP-123", "bodyData": map[string]any{}}}); err == nil {
		t.Fatal("unresolved JSON custom scalar accepted")
	}
	list, err := linear.Normalize(`mutation($input:CommentCreateInput!){commentCreate(input:$input){success}}`, "", map[string]any{"input": map[string]any{"issueId": "APP-123", "body": "local only", "subscriberIds": "user-id"}})
	if err != nil {
		t.Fatal(err)
	}
	ids := list.Fields[0].Arguments["input"].(map[string]any)["subscriberIds"].([]any)
	if len(ids) != 1 || ids[0] != "user-id" {
		t.Fatal("singleton list coercion lost")
	}
}
