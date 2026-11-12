package schema

import (
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// plainYAML rejects the YAML features that let one written value appear in
// several places or change type, so a file reads the way it is applied.
type plainYAML struct{ rejected bool }

func (p *plainYAML) Visit(node ast.Node) ast.Visitor {
	switch node.(type) {
	case *ast.AnchorNode, *ast.AliasNode, *ast.MergeKeyNode, *ast.TagNode:
		p.rejected = true
	}
	return p
}

// DecodeDocument reads one administrator-authored document written as JSON or
// YAML and returns the value DecodeJSON would return for the same content.
//
// It is for files an administrator owns. Caller request bodies stay on
// DecodeJSON: the YAML parser is not bounded for hostile input.
func DecodeDocument(data []byte) (any, error) {
	if len(data) > MaxDocumentBytes {
		return nil, errors.New("document too large")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("invalid document UTF-8")
	}
	// Strict JSON is read as before, so numbers keep their exact text and a
	// pinned schema digest does not move.
	if value, err := DecodeJSON(data); err == nil {
		return value, nil
	}
	file, err := parser.ParseBytes(data, 0)
	if err != nil || len(file.Docs) != 1 || file.Docs[0].Body == nil {
		return nil, errors.New("document must be one YAML or JSON document")
	}
	plain := &plainYAML{}
	ast.Walk(plain, file.Docs[0])
	if plain.rejected {
		return nil, errors.New("document must not use YAML anchors, aliases, merge keys or tags")
	}
	var document any
	if err = yaml.NodeToValue(file.Docs[0].Body, &document, yaml.Strict()); err != nil {
		return nil, errors.New("invalid YAML document")
	}
	// Re-reading as strict JSON gives every later step one value model and
	// refuses what JSON cannot carry, such as NaN.
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("invalid YAML value")
	}
	return DecodeJSON(encoded)
}
