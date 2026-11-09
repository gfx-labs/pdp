package schema_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gfx-labs/pdp/internal/schema"
)

func catalogContract(t *testing.T, catalog schema.Catalog, id string) map[string]any {
	t.Helper()
	for _, operation := range catalog.Operations {
		if operation.ID != id {
			continue
		}
		value, err := schema.DecodeJSON(operation.Contract)
		if err != nil {
			t.Fatalf("operation %s has invalid contract: %v", id, err)
		}
		return value.(map[string]any)
	}
	t.Fatalf("operation %s missing", id)
	return nil
}

func TestProviderCatalogValidationContracts(t *testing.T) {
	data, err := os.ReadFile("testdata/github-rest.json")
	if err != nil {
		t.Fatal(err)
	}
	github, err := schema.CompileREST(data)
	if err != nil {
		t.Fatal(err)
	}
	contract := catalogContract(t, github.Catalog(), "issues/list-comments")
	parameters := map[string]map[string]any{}
	for _, value := range contract["parameters"].([]any) {
		p := value.(map[string]any)
		parameters[p["in"].(string)+":"+p["name"].(string)] = p
	}
	owner, page := parameters["path:owner"], parameters["query:per_page"]
	if owner["required"] != true || owner["schema"].(map[string]any)["type"] != "string" || page["required"] != false || page["schema"].(map[string]any)["type"] != "integer" {
		t.Fatalf("missing inspectable path/query contract: %#v", parameters)
	}
	contract = catalogContract(t, github.Catalog(), "issues/create-comment")
	body := contract["body"].(map[string]any)
	bodySchema := body["schema"].(map[string]any)
	if body["required"] != true || body["content_type"] != "application/json" || contract["closed_objects"] != true || !reflect.DeepEqual(bodySchema["required"], []any{"body"}) || bodySchema["properties"].(map[string]any)["body"].(map[string]any)["type"] != "string" {
		t.Fatalf("missing inspectable body contract: %#v", contract)
	}

	data, err = os.ReadFile("testdata/linear.graphql")
	if err != nil {
		t.Fatal(err)
	}
	linear, err := schema.CompileGraphQL(data)
	if err != nil {
		t.Fatal(err)
	}
	contract = catalogContract(t, linear.Catalog(), "Mutation.commentCreate")
	arguments := contract["arguments"].(map[string]any)
	input := contract["inputs"].(map[string]any)["CommentCreateInput"].(map[string]any)
	fields := input["fields"].(map[string]any)
	output := contract["return"].(map[string]any)
	if arguments["input"].(map[string]any)["type"] != "CommentCreateInput!" || fields["issueId"].(map[string]any)["type"] != "String" || fields["projectId"].(map[string]any)["type"] != "String" || output["type"] != "CommentPayload!" || output["definition"].(map[string]any)["fields"].(map[string]any)["success"].(map[string]any)["type"] != "Boolean!" {
		t.Fatalf("missing full argument/input/return contract: %#v", contract)
	}
	changed, err := schema.CompileGraphQL([]byte(strings.Replace(string(data), "issueId: String", "issueId: String!", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(contract, catalogContract(t, changed.Catalog(), "Mutation.commentCreate")) {
		t.Fatal("same-ID input drift left contract unchanged")
	}
	if diff := schema.Diff(linear.Catalog(), changed.Catalog()); !reflect.DeepEqual(diff.Changed, []string{"Mutation.commentCreate"}) {
		t.Fatalf("input contract drift missing from diff: %#v", diff)
	}

	// Returned raw JSON must not expose mutable compiled snapshot storage.
	catalog := linear.Catalog()
	original := append([]byte(nil), catalog.Operations[0].Contract...)
	catalog.Operations[0].Contract[0] = '!'
	if !bytes.Equal(linear.Catalog().Operations[0].Contract, original) {
		t.Fatal("catalog mutation changed compiled schema")
	}
	encoded, err := json.Marshal(linear.Catalog())
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Operations []struct {
			Contract map[string]any `json:"contract"`
		} `json:"operations"`
	}
	if err = json.Unmarshal(encoded, &wire); err != nil || len(wire.Operations) == 0 || wire.Operations[0].Contract == nil {
		t.Fatalf("catalog contract is not a structured JSON object: %v", err)
	}
}
