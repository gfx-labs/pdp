package schema_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gfx-labs/pdp/pkg/schema"
)

func publicSDL(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/swapi.graphql")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func graphqlSchema(t *testing.T) *schema.GraphQLSchema {
	t.Helper()
	s, e := schema.CompileGraphQL(publicSDL(t))
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// Project only the unsupported server prefix and format annotations from the
// recorded public document. All operation, reference and input shapes stay real.
func petstore(t *testing.T) map[string]any {
	t.Helper()
	b, e := os.ReadFile("testdata/oai-petstore.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = schema.CompileREST(b); e == nil {
		t.Fatal("unsupported original server base path accepted")
	}
	raw, e := schema.DecodeJSON(b)
	if e != nil {
		t.Fatal(e)
	}
	m := raw.(map[string]any)
	delete(m, "servers")
	var project func(any)
	project = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			delete(x, "format")
			for _, v := range x {
				project(v)
			}
		case []any:
			for _, v := range x {
				project(v)
			}
		}
	}
	project(m)
	return m
}
func restSchema(t *testing.T, m map[string]any) *schema.RESTSchema {
	t.Helper()
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	s, e := schema.CompileREST(b)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func paths(m map[string]any) map[string]any { return m["paths"].(map[string]any) }
func listParameter(m map[string]any) map[string]any {
	return paths(m)["/pets"].(map[string]any)["get"].(map[string]any)["parameters"].([]any)[0].(map[string]any)["schema"].(map[string]any)
}

func TestRESTNormalizationBoundary(t *testing.T) {
	s := restSchema(t, petstore(t))
	req := httptest.NewRequest("GET", "http://provider/pets?limit=12", nil)
	r, e := s.Normalize(req)
	if e != nil {
		t.Fatal(e)
	}
	if r.OperationID != "listPets" || r.Query["limit"] != int64(12) {
		t.Fatalf("wrong typed normalization: %#v", r)
	}
	body := `{"id":15,"name":"Fido","tag":"dog"}`
	req = httptest.NewRequest("POST", "http://provider/pets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r, e = s.Normalize(req)
	if e != nil {
		t.Fatal(e)
	}
	if r.Body.(map[string]any)["id"] != int64(15) {
		t.Fatal("body integer was not typed")
	}
	restored, _ := io.ReadAll(req.Body)
	if string(restored) != body {
		t.Fatal("normalizer consumed forwarding body")
	}
	cases := []struct{ name, method, target, body string }{
		{"duplicate query", "GET", "/pets?limit=1&limit=2", ""},
		{"encoded duplicate", "GET", "/pets?limit=1&%6cimit=2", ""},
		{"unknown query", "GET", "/pets?admin=true", ""},
		{"out of bounds", "GET", "/pets?limit=101", ""},
		{"wrong query type", "GET", "/pets?limit=true", ""},
		{"encoded slash", "GET", "/pets/a%2fb", ""},
		{"encoded dot", "GET", "/pets/%2e%2e", ""},
		{"double encoding", "GET", "/pets/a%252fb", ""},
		{"double slash", "GET", "/pets//x", ""},
		{"dot segment", "GET", "/pets/../x", ""},
		{"unknown field", "POST", "/pets", `{"id":1,"name":"Fido","admin":true}`},
		{"duplicate member", "POST", "/pets", `{"id":1,"name":"Fido","name":"other"}`},
		{"missing required", "POST", "/pets", `{"name":"Fido"}`},
		{"null required", "POST", "/pets", `{"id":1,"name":null}`},
		{"wrong body type", "POST", "/pets", `{"id":"1","name":"Fido"}`},
		{"trailing JSON", "POST", "/pets", `{"id":1,"name":"Fido"}{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://provider"+tc.target, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if _, e := s.Normalize(req); e == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}
func TestRESTSchemaRejectionsAndLiteralPriority(t *testing.T) {
	base := petstore(t)
	pathItem := paths(base)["/pets/{petId}"].(map[string]any)
	literal := map[string]any{"get": map[string]any{"operationId": "me", "responses": map[string]any{"200": map[string]any{"description": "ok"}}}}
	paths(base)["/pets/me"] = literal
	s := restSchema(t, base)
	r, e := s.Normalize(httptest.NewRequest("GET", "http://provider/pets/me", nil))
	if e != nil || r.OperationID != "me" {
		t.Fatalf("literal did not outrank template: %#v %v", r, e)
	}
	paths(base)["/pets/{other}"] = pathItem
	b, _ := json.Marshal(base)
	if _, e := schema.CompileREST(b); e == nil {
		t.Fatal("equivalent templates accepted")
	}
	crossing := petstore(t)
	paths(crossing)["/{kind}/fixed"] = map[string]any{"get": map[string]any{"operationId": "crossing", "parameters": []any{map[string]any{"name": "kind", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}}}}
	b, _ = json.Marshal(crossing)
	if _, err := schema.CompileREST(b); err == nil {
		t.Fatal("crossing templated routes accepted")
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"security", func(m map[string]any) { m["security"] = []any{map[string]any{"bearer": []any{}}} }},
		{"unknown ref", func(m map[string]any) {
			m["components"].(map[string]any)["schemas"].(map[string]any)["Unused"] = map[string]any{"$ref": "#/components/schemas/Missing"}
		}},
		{"recursive", func(m map[string]any) {
			m["components"].(map[string]any)["schemas"].(map[string]any)["Unused"] = map[string]any{"$ref": "#/components/schemas/Unused"}
		}},
		{"oneOf", func(m map[string]any) { listParameter(m)["oneOf"] = []any{map[string]any{"type": "integer"}} }},
		{"open object", func(m map[string]any) {
			m["components"].(map[string]any)["schemas"].(map[string]any)["Pet"].(map[string]any)["additionalProperties"] = true
		}},
		{"unknown response ref", func(m map[string]any) {
			paths(m)["/pets"].(map[string]any)["get"].(map[string]any)["responses"] = map[string]any{"200": map[string]any{"$ref": "#/components/schemas/Absent"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := petstore(t)
			tc.change(m)
			b, _ := json.Marshal(m)
			if _, e := schema.CompileREST(b); e == nil {
				t.Fatal("unsupported schema accepted")
			}
		})
	}
}
func TestRESTExactBoundsAndDiff(t *testing.T) {
	m := petstore(t)
	listParameter(m)["minimum"] = json.Number("9007199254740993")
	delete(listParameter(m), "maximum")
	before := restSchema(t, m)
	if _, e := before.Normalize(httptest.NewRequest("GET", "http://provider/pets?limit=9007199254740992", nil)); e == nil {
		t.Fatal("integer rounded through minimum")
	}
	if _, e := before.Normalize(httptest.NewRequest("GET", "http://provider/pets?limit=9007199254740993", nil)); e != nil {
		t.Fatal(e)
	}
	listParameter(m)["minimum"] = json.Number("9007199254740994")
	after := restSchema(t, m)
	diff := schema.Diff(before.Catalog(), after.Catalog())
	if !reflect.DeepEqual(diff.Changed, []string{"listPets"}) {
		t.Fatalf("bound drift missing from diff: %#v", diff)
	}
	if e := after.Catalog().ValidateReferences([]string{"unlisted-operation"}); e == nil {
		t.Fatal("unknown policy reference accepted")
	}
	b, _ := json.Marshal(m)
	var pretty bytes.Buffer
	json.Indent(&pretty, b, "", "  ")
	again, e := schema.CompileREST(pretty.Bytes())
	if e != nil || again.Digest() != after.Digest() {
		t.Fatal("JSON whitespace changed digest")
	}
}

func TestGraphQLFieldOccurrences(t *testing.T) {
	s := graphqlSchema(t)
	query := `query Selected($id: ID! = "1000", $withName: Boolean! = true) {
 first: human(id: $id) { ...Details ...Details h:height(unit:FOOT) }
 second: human(id:"2000") { height }
 hidden: human(id:"3000") @skip(if:true) { name }
 } fragment Details on Human { name @include(if:$withName) height friends { name } }
 query Other { hero { id } }`
	r, e := s.Normalize(query, "Selected", nil)
	if e != nil {
		t.Fatal(e)
	}
	coords := []string{}
	for _, f := range r.Fields {
		coords = append(coords, f.Coordinate)
	}
	expected := []string{"Query.human", "Human.name", "Human.height", "Human.friends", "Character.name", "Human.name", "Human.height", "Human.friends", "Character.name", "Human.height", "Query.human", "Human.height", "Query.human", "Human.name"}
	if !reflect.DeepEqual(coords, expected) {
		t.Fatalf("occurrences lost, reordered or skipped incorrectly: %v", coords)
	}
	if r.Fields[0].Arguments["id"] != "1000" || r.Fields[10].Arguments["id"] != "2000" || r.Fields[2].Arguments["unit"] != "METER" || r.Fields[9].Arguments["unit"] != "FOOT" {
		t.Fatalf("wrong per-occurrence arguments: %#v", r.Fields)
	}
	if !reflect.DeepEqual(r.Fields[4].Path, []string{"first", "friends", "name"}) || !reflect.DeepEqual(r.Fields[9].Path, []string{"first", "h"}) {
		t.Fatal("alias/nested path lost")
	}
	r, e = s.Normalize(`query($id:ID!){human(id:$id){height}}`, "", map[string]any{"id": "1234567890123456789"})
	if e != nil || r.Fields[0].Arguments["id"] != "1234567890123456789" {
		t.Fatalf("exact numeric ID lost: %#v %v", r, e)
	}
	if _, e = s.Normalize(`query($id:ID!){human(id:$id){height}}`, "", map[string]any{"id": json.Number("1234567890123456789")}); e == nil {
		t.Fatal("transport-ambiguous numeric ID accepted")
	}
}
func TestGraphQLCoercionAndDefaults(t *testing.T) {
	sdl := strings.Replace(string(publicSDL(t)), "commentary: String\n    # Favorite", `commentary: String = "default comment"
    # Favorite`, 1)
	s, e := schema.CompileGraphQL([]byte(sdl))
	if e != nil {
		t.Fatal(e)
	}
	query := `mutation Write($episode:Episode!=JEDI,$review:ReviewInput!){createReview(episode:$episode,review:$review){stars commentary}}`
	vars := map[string]any{"review": map[string]any{"stars": json.Number("5"), "favorite_color": map[string]any{"red": 1, "green": 2, "blue": 3}}}
	r, e := s.Normalize(query, "Write", vars)
	if e != nil {
		t.Fatal(e)
	}
	review := r.Fields[0].Arguments["review"].(map[string]any)
	if review["commentary"] != "default comment" || review["stars"] != int64(5) || r.Fields[0].Arguments["episode"] != "JEDI" {
		t.Fatalf("defaults not materialized: %#v", r)
	}
	if _, ok := vars["review"].(map[string]any)["commentary"]; ok {
		t.Fatal("normalization mutated caller variables")
	}
	for _, v := range []any{"5", json.Number("5.5"), json.Number("2147483648")} {
		_, e = s.Normalize(query, "Write", map[string]any{"review": map[string]any{"stars": v}})
		if e == nil {
			t.Fatalf("invalid Int accepted: %v", v)
		}
	}
	_, e = s.Normalize(query, "Write", map[string]any{"episode": "jedi", "review": map[string]any{"stars": 5}})
	if e == nil {
		t.Fatal("case-insensitive enum accepted")
	}
	_, e = s.Normalize(query, "Write", map[string]any{"review": map[string]any{"stars": 5, "unknown": true}})
	if e == nil {
		t.Fatal("unknown input accepted")
	}
}
func TestGraphQLRejectedAndEnvelope(t *testing.T) {
	s := graphqlSchema(t)
	for _, q := range []string{
		`query A{hero{id}} query B{hero{id}}`,
		`subscription {reviewAdded{stars}}`,
		`{hero{missing}}`,
		`{hero{...Cycle}} fragment Cycle on Character{...Cycle}`,
		`{hero{__typename}}`,
		`{hero @defer{id}}`,
		`{hero{...F}} fragment F on Character{name @include(if:1)}`,
	} {
		if _, e := s.Normalize(q, "", nil); e == nil {
			t.Fatalf("unsafe GraphQL accepted: %s", q)
		}
	}
	if _, e := s.Normalize(`{hero{id}}`, "", map[string]any{"unused": true}); e == nil {
		t.Fatal("unknown variable accepted")
	}
	for _, body := range []string{`[{"query":"{hero{id}}"}]`, `{"query":"{hero{id}}","query":"{hero{name}}"}`, `{"query":"{hero{id}}","extensions":{"persistedQuery":{}}}`, `{"query":"{hero{id}}","variables":[]}`} {
		req := httptest.NewRequest("POST", "http://provider/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if _, e := s.NormalizeHTTP(req); e == nil {
			t.Fatalf("unsafe envelope accepted: %s", body)
		}
	}
	req := httptest.NewRequest("POST", "http://provider/graphql", strings.NewReader(`{"query":"{hero{id}}"}`))
	req.Header.Set("Content-Type", "application/json")
	if _, e := s.NormalizeHTTP(req); e != nil {
		t.Fatal(e)
	}
}
func TestGraphQLDigestDefaultsAndReachableDiff(t *testing.T) {
	original := publicSDL(t)
	a, e := schema.CompileGraphQL(original)
	if e != nil {
		t.Fatal(e)
	}
	b, e := schema.CompileGraphQL([]byte("# whitespace\n" + string(original)))
	if e != nil || a.Digest() != b.Digest() {
		t.Fatal("trivia changed digest")
	}
	changed := strings.Replace(string(original), "red: Int!", "red: Float!", 1)
	c, e := schema.CompileGraphQL([]byte(changed))
	if e != nil {
		t.Fatal(e)
	}
	diff := schema.Diff(a.Catalog(), c.Catalog())
	if !reflect.DeepEqual(diff.Changed, []string{"Mutation.createReview"}) {
		t.Fatalf("nested input drift missing: %#v", diff)
	}
	changed = strings.Replace(string(original), "unit: LengthUnit = METER", "unit: LengthUnit = FOOT", 1)
	c, e = schema.CompileGraphQL([]byte(changed))
	if e != nil {
		t.Fatal(e)
	}
	diff = schema.Diff(a.Catalog(), c.Catalog())
	if !reflect.DeepEqual(diff.Changed, []string{"Human.height", "Query.human"}) {
		t.Fatalf("default drift missing: %#v", diff)
	}
	if _, e = schema.CompileGraphQL([]byte("type Query { missing: Missing }")); e == nil {
		t.Fatal("unknown schema reference accepted")
	}
}

func TestUnicodeAmbiguityAndExpansionLimits(t *testing.T) {
	for _, raw := range []string{`{"name":"\ud800"}`, `{"name":"\udc00"}`, string([]byte{'"', 0xff, '"'})} {
		if _, err := schema.DecodeJSON([]byte(raw)); err == nil {
			t.Fatal("ambiguous Unicode accepted")
		}
	}
	if _, err := schema.DecodeJSON([]byte(`{"name":"\ud83d\ude00","literal":"\\ud800"}`)); err != nil {
		t.Fatal(err)
	}
	s := graphqlSchema(t)
	if _, err := s.Normalize(`{human(id:"\ud800"){id}}`, "", nil); err == nil {
		t.Fatal("ambiguous GraphQL literal accepted")
	}
	if _, err := s.Normalize(`{human(id:"\u{1f600}"){id}}`, "", nil); err != nil {
		t.Fatal(err)
	}
	query := `{human(id:"1000"){...F13}} fragment F0 on Human{name}`
	for i := 1; i <= 13; i++ {
		previous := "F" + strconv.Itoa(i-1)
		query += " fragment F" + strconv.Itoa(i) + " on Human{..." + previous + " ..." + previous + "}"
	}
	if _, err := s.Normalize(query, "", nil); err == nil || !strings.Contains(err.Error(), "expansion limit") {
		t.Fatalf("fragment expansion not bounded: %v", err)
	}
	deep := `{hero{` + strings.Repeat("friends{", 65) + "id" + strings.Repeat("}", 67)
	if _, err := s.Normalize(deep, "", nil); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("selection depth not bounded: %v", err)
	}
	if _, err := schema.CompileGraphQL([]byte(`directive @include(if:String!) on FIELD
type Query{hello:String}`)); err == nil {
		t.Fatal("builtin directive redefinition accepted")
	}
	repeated := `query($text:String){`
	for i := 0; i < 50; i++ {
		repeated += "f" + strconv.Itoa(i) + `:search(text:$text){...on Human{id}} `
	}
	repeated += "}"
	if _, err := s.Normalize(repeated, "", map[string]any{"text": strings.Repeat("x", 100000)}); err == nil || !strings.Contains(err.Error(), "expansion limit") {
		t.Fatalf("repeated argument expansion unbounded: %v", err)
	}
}
