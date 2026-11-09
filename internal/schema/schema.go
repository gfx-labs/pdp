// Package schema implements a deliberately narrow, fail-closed API schema boundary.
package schema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxDocumentBytes = 4 << 20
const MaxBodyBytes = 1 << 20
const maxDepth = 64

// Request contains schema-validated values, not trusted identity or classification.
type Request struct {
	Protocol      string            `json:"protocol"`
	OperationID   string            `json:"operation_id"`
	Method        string            `json:"method,omitempty"`
	PathTemplate  string            `json:"path_template,omitempty"`
	Path          map[string]any    `json:"path,omitempty"`
	Query         map[string]any    `json:"query,omitempty"`
	Body          any               `json:"body,omitempty"`
	OperationType string            `json:"operation_type,omitempty"`
	OperationName string            `json:"operation_name,omitempty"`
	Variables     map[string]any    `json:"variables,omitempty"`
	Fields        []FieldOccurrence `json:"fields,omitempty"`
}
type RESTRequest = Request
type GraphQLRequest = Request

type FieldOccurrence struct {
	Coordinate string         `json:"coordinate"`
	Path       []string       `json:"path"`
	Arguments  map[string]any `json:"arguments"`
}

type Operation struct {
	ID         string          `json:"id"`
	Method     string          `json:"method,omitempty"`
	Path       string          `json:"path,omitempty"`
	Type       string          `json:"type,omitempty"`
	Coordinate string          `json:"coordinate,omitempty"`
	Signature  string          `json:"signature"`
	Contract   json.RawMessage `json:"contract,omitempty"`
}
type Catalog struct {
	Protocol   string      `json:"protocol"`
	Digest     string      `json:"digest"`
	Operations []Operation `json:"operations"`
}
type Changes struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

func (c Catalog) HasOperation(id string) bool {
	for _, op := range c.Operations {
		if op.ID == id {
			return true
		}
	}
	return false
}
func (c Catalog) ValidateReferences(ids []string) error {
	for _, id := range ids {
		if !c.HasOperation(id) {
			return fmt.Errorf("unknown %s operation %q", c.Protocol, id)
		}
	}
	return nil
}
func Diff(before, after Catalog) Changes {
	out := Changes{Added: []string{}, Removed: []string{}, Changed: []string{}}
	a, b := map[string]Operation{}, map[string]Operation{}
	for _, op := range before.Operations {
		a[op.ID] = op
	}
	for _, op := range after.Operations {
		b[op.ID] = op
	}
	for id, op := range a {
		next, ok := b[id]
		if !ok {
			out.Removed = append(out.Removed, id)
		} else if digest(op) != digest(next) {
			out.Changed = append(out.Changed, id)
		}
	}
	for id := range b {
		if _, ok := a[id]; !ok {
			out.Added = append(out.Added, id)
		}
	}
	sort.Strings(out.Added)
	sort.Strings(out.Removed)
	sort.Strings(out.Changed)
	return out
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func cloneCatalog(c Catalog) Catalog {
	c.Operations = append([]Operation(nil), c.Operations...)
	for i := range c.Operations {
		c.Operations[i].Contract = append(json.RawMessage(nil), c.Operations[i].Contract...)
	}
	return c
}

// DecodeJSON rejects duplicate object members, trailing data and excessive nesting.
func DecodeJSON(data []byte) (any, error) {
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("JSON document too large")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid JSON UTF-8")
	}
	if err := validJSONSurrogates(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return value, nil
}

func validJSONSurrogates(data []byte) error {
	return validStringSurrogates(data, false)
}
func validStringSurrogates(data []byte, braced bool) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		if braced && i+1 < len(data) && data[i+1] == '{' {
			end := i + 2
			for end < len(data) && data[end] != '}' {
				end++
			}
			if end == len(data) {
				return fmt.Errorf("invalid Unicode escape")
			}
			code, err := strconv.ParseUint(string(data[i+2:end]), 16, 32)
			if err != nil || code > utf8.MaxRune || (code >= 0xD800 && code <= 0xDFFF) {
				return fmt.Errorf("invalid Unicode escape")
			}
			i = end
			continue
		}
		if i+4 >= len(data) {
			return fmt.Errorf("invalid Unicode escape")
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return fmt.Errorf("invalid Unicode escape")
		}
		i += 4
		if code >= 0xDC00 && code <= 0xDFFF {
			return fmt.Errorf("unpaired Unicode surrogate")
		}
		if code < 0xD800 || code > 0xDBFF {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return fmt.Errorf("unpaired Unicode surrogate")
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return fmt.Errorf("unpaired Unicode surrogate")
		}
		i += 6
	}
	return nil
}
func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("JSON nesting limit exceeded")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			t, e := dec.Token()
			if e != nil {
				return nil, e
			}
			k, ok := t.(string)
			if !ok {
				return nil, fmt.Errorf("invalid object key")
			}
			if _, ok = obj[k]; ok {
				return nil, fmt.Errorf("duplicate JSON member %q", k)
			}
			v, e := decodeValue(dec, depth+1)
			if e != nil {
				return nil, e
			}
			obj[k] = v
		}
		_, err = dec.Token()
		return obj, err
	case '[':
		arr := []any{}
		for dec.More() {
			v, e := decodeValue(dec, depth+1)
			if e != nil {
				return nil, e
			}
			arr = append(arr, v)
		}
		_, err = dec.Token()
		return arr, err
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}
func readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, MaxBodyBytes+1))
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBodyBytes {
		return nil, fmt.Errorf("request body too large")
	}
	return data, nil
}
func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func object(v any, context string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	return m, nil
}
func allowed(m map[string]any, names string) error {
	for k := range m {
		if strings.HasPrefix(k, "x-") {
			return fmt.Errorf("unsupported extension %q", k)
		}
		if !strings.Contains(" "+names+" ", " "+k+" ") {
			return fmt.Errorf("unsupported construct %q", k)
		}
	}
	return nil
}
