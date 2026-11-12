package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// inputValue hand-writes the names and omission rules that the json tags on
// Input declare. A field added to Input and not to inputValue fails here.
func TestInputValueMatchesJSON(t *testing.T) {
	uid := uint32(1000)
	inputs := map[string]Input{
		"every-field": {
			Version:     InputVersion,
			Identity:    Identity{ID: "uid:1000", AuthMethod: "unix", SPIFFEID: "spiffe://example.org/w", UID: &uid, IP: "10.0.0.1"},
			Protocol:    ProtocolHTTP,
			Destination: Destination{Scheme: "https", Host: "api.example.test", Port: 443, Addresses: []string{"192.0.2.1"}},
			Binding:     "binding", Plugin: "plugin", SchemaDigest: "sha256:digest",
			HTTP: &HTTPInput{
				Method: "POST", Path: "/a", PathParams: map[string]string{"owner": "o"},
				Query:           map[string][]string{"q": {"1", "bad\xffbytes"}, "empty": {}},
				NormalizedQuery: map[string]any{"q": json.Number("1e0"), "list": []any{json.Number("9007199254740993"), nil, true}},
				Body: map[string]any{
					"text": "<a>&\u2028", "nested": map[string]any{}, "items": []any{},
					"float": 1.5, "int": 7, "strings": []string{"x"}, "typed": Resource{Type: "issue", ID: "1"},
				},
			},
			Operations: []OperationInput{{ID: "op", Resources: []Resource{{Type: "issue", ID: "1"}}}, {ID: "plain"}},
			GraphQL: []FieldOccurrence{
				{Coordinate: "Query.issue", Path: []string{"issue"}, ResponsePath: []string{"alias"}, ParentType: "Query", Field: "issue", Alias: "alias", Arguments: map[string]any{"id": "1"}},
				{Coordinate: "Issue.id"},
				{Coordinate: "Issue.title", Path: []string{}, Arguments: map[string]any{}},
			},
			OperationType: "query", OperationName: "Name", Variables: map[string]any{"id": "1"},
		},
		"empty-collections": {
			Version: InputVersion, Identity: Identity{ID: "uid:0", UID: new(uint32)}, Protocol: ProtocolHTTP,
			Destination: Destination{Addresses: []string{}},
			HTTP:        &HTTPInput{PathParams: map[string]string{}, Query: map[string][]string{}, NormalizedQuery: map[string]any{}, Body: false},
			Operations:  []OperationInput{}, GraphQL: []FieldOccurrence{}, Variables: map[string]any{},
		},
		"tunnel": {
			Version: InputVersion, Identity: Identity{ID: "ip:10.0.0.1"}, Protocol: ProtocolTunnel,
			Destination: Destination{Scheme: "tcp", Host: "db.example.test", Port: 5432},
		},
	}
	// The packs' explain inputs are the shapes the documented policies read.
	files, err := filepath.Glob("../../examples/packs/*/explain/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no pack explain inputs found: %v", err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var input Input
		if err := decodeJSON(raw, &input); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		inputs[file] = input
	}
	for name, input := range inputs {
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var plain any
		if err := decodeJSON(encoded, &plain); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := ast.InterfaceToValue(plain)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := inputValue(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Compare(want) != 0 {
			t.Errorf("%s:\n got %v\nwant %v", name, got, want)
		}
	}
}
