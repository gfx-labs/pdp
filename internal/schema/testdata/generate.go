//go:build ignore

// Generates restricted request-surface projections from pinned public sources.
// Run from the repository root with downloaded source files as arguments.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/parser"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: go run internal/schema/testdata/generate.go GITHUB_JSON LINEAR_SDL")
	}
	generateGitHub(os.Args[1])
	generateLinear(os.Args[2])
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func obj(v any) map[string]any { return v.(map[string]any) }
func readPinned(path, expected string) []byte {
	data, err := os.ReadFile(path)
	must(err)
	if fmt.Sprintf("%x", sha256.Sum256(data)) != expected {
		panic("source digest mismatch: " + path)
	}
	return data
}
func generateGitHub(path string) {
	data := readPinned(path, "b8973e498305c0e45891c45a109901f9caf6ecbf8ad0e53404a7947c503e120f")
	var err error
	var source map[string]any
	must(json.Unmarshal(data, &source))
	sourcePaths := obj(source["paths"])
	parameters := obj(obj(source["components"])["parameters"])
	selected := map[string][]string{"/repos/{owner}/{repo}": {"get"}, "/repos/{owner}/{repo}/issues/{issue_number}": {"get"}, "/repos/{owner}/{repo}/issues/{issue_number}/comments": {"get", "post"}}
	paths := map[string]any{}
	for path, methods := range selected {
		item := map[string]any{}
		for _, method := range methods {
			original := obj(obj(sourcePaths[path])[method])
			operation := map[string]any{"operationId": original["operationId"]}
			params := []any{}
			for _, entry := range original["parameters"].([]any) {
				p := obj(entry)
				if ref, ok := p["$ref"].(string); ok {
					p = obj(parameters[strings.TrimPrefix(ref, "#/components/parameters/")])
				}
				if p["name"] == "since" {
					continue
				}
				b, err := json.Marshal(p)
				must(err)
				var copied map[string]any
				must(json.Unmarshal(b, &copied))
				delete(obj(copied["schema"]), "default")
				params = append(params, copied)
			}
			operation["parameters"] = params
			if body, ok := original["requestBody"]; ok {
				operation["requestBody"] = body
			}
			responses := map[string]any{}
			for code, response := range obj(original["responses"]) {
				description := obj(response)["description"]
				if description == nil {
					description = "Provider response"
				}
				responses[code] = map[string]any{"description": description}
			}
			operation["responses"] = responses
			item[method] = operation
		}
		paths[path] = item
	}
	projected := map[string]any{"openapi": source["openapi"], "info": map[string]any{"title": "GitHub restricted request projection", "version": "2f8f80e47ea4d3292cf4e37ba9d9b25475e06140"}, "paths": paths}
	data, err = json.MarshalIndent(projected, "", "  ")
	must(err)
	must(os.WriteFile("internal/schema/testdata/github-rest.json", append(data, '\n'), 0644))
}
func generateLinear(path string) {
	data := readPinned(path, "dc0f838785760f8daa692e438fcd15071c5bc39c6997758d5c2d303364f98e56")
	doc, err := parser.ParseSchema(&ast.Source{Name: "linear-original.graphql", Input: string(data)})
	must(err)
	selections := map[string][]string{"Query": {"issue"}, "Mutation": {"commentCreate"}, "Issue": {"id", "identifier", "title", "description", "url"}, "Comment": {"id", "body", "url", "issue"}, "CommentPayload": {"comment", "success", "lastSyncId"}}
	keep := map[string]bool{"CommentCreateInput": true, "DateTime": true, "JSON": true, "Node": true}
	out := &ast.SchemaDocument{}
	for _, def := range doc.Definitions {
		if names, ok := selections[def.Name]; ok {
			fields := ast.FieldList{}
			for _, name := range names {
				field := def.Fields.ForName(name)
				if field == nil {
					panic(fmt.Sprintf("missing %s.%s", def.Name, name))
				}
				fields = append(fields, field)
			}
			def.Fields = fields
			out.Definitions = append(out.Definitions, def)
		} else if keep[def.Name] {
			out.Definitions = append(out.Definitions, def)
		}
	}
	f, err := os.Create("internal/schema/testdata/linear.graphql")
	must(err)
	formatter.NewFormatter(f).FormatSchemaDocument(out)
	must(f.Close())
}
