package schema

import (
	"encoding/json"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type valueSchema struct {
	Type       string                  `json:"type"`
	Properties map[string]*valueSchema `json:"properties,omitempty"`
	Required   []string                `json:"required,omitempty"`
	Items      *valueSchema            `json:"items,omitempty"`
	Enum       []any                   `json:"enum,omitempty"`
	Nullable   bool                    `json:"nullable,omitempty"`
	Min        *json.Number            `json:"minimum,omitempty"`
	Max        *json.Number            `json:"maximum,omitempty"`
	MinLength  *int                    `json:"minLength,omitempty"`
	MaxLength  *int                    `json:"maxLength,omitempty"`
	MinItems   *int                    `json:"minItems,omitempty"`
	MaxItems   *int                    `json:"maxItems,omitempty"`
	Pattern    string                  `json:"pattern,omitempty"`
	pattern    *regexp.Regexp
}
type restParameter struct {
	Name, In string
	Required bool
	Schema   *valueSchema
}
type restOperation struct {
	ID, Method, Template string
	Segments             []string
	Parameters           []restParameter
	Body                 *valueSchema
	BodyRequired         bool
}
type RESTSchema struct {
	operations []restOperation
	catalog    Catalog
}

func CompileREST(spec []byte) (*RESTSchema, error) {
	raw, err := DecodeJSON(spec)
	if err != nil {
		return nil, err
	}
	doc, err := object(raw, "OpenAPI")
	if err != nil {
		return nil, err
	}
	if err = allowed(doc, "openapi info paths components servers tags externalDocs security"); err != nil {
		return nil, err
	}
	version, _ := doc["openapi"].(string)
	if !regexp.MustCompile(`^3\.(0|1)\.[0-9]+$`).MatchString(version) {
		return nil, fmt.Errorf("only OpenAPI 3.0 and 3.1 JSON are supported")
	}
	if err = emptySecurity(doc); err != nil {
		return nil, err
	}
	if servers, ok := doc["servers"]; ok {
		arr, ok := servers.([]any)
		if !ok {
			return nil, fmt.Errorf("servers must be array")
		}
		for _, x := range arr {
			m, e := object(x, "server")
			if e != nil {
				return nil, e
			}
			if e = allowed(m, "url description"); e != nil {
				return nil, e
			}
			u, ok := m["url"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid server URL")
			}
			parsed, e := url.Parse(u)
			if e != nil || u == "" || strings.ContainsAny(u, "{}") || parsed.User != nil || parsed.Opaque != "" || (parsed.Scheme != "" && parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
				return nil, fmt.Errorf("server base paths and variables are unsupported")
			}
		}
	}
	components := map[string]any{}
	if v, ok := doc["components"]; ok {
		components, err = object(v, "components")
		if err != nil {
			return nil, err
		}
		if err = allowed(components, "schemas"); err != nil {
			return nil, err
		}
	}
	definitions := map[string]any{}
	if v, ok := components["schemas"]; ok {
		definitions, err = object(v, "component schemas")
		if err != nil {
			return nil, err
		}
	}
	compiler := restCompiler{definitions: definitions, remaining: new(int)}
	*compiler.remaining = 65536
	if err = validateRESTReferences(doc, definitions, 0); err != nil {
		return nil, err
	}
	for _, name := range keys(definitions) {
		if _, err = compiler.compile(definitions[name], map[string]bool{}, 0); err != nil {
			return nil, fmt.Errorf("schema %s: %w", name, err)
		}
	}
	paths, err := object(doc["paths"], "paths")
	if err != nil {
		return nil, err
	}
	out := &RESTSchema{}
	ids := map[string]bool{}
	shapes := map[string]string{}
	for _, path := range keys(paths) {
		segments, e := templateSegments(path)
		if e != nil {
			return nil, e
		}
		shape := make([]string, len(segments))
		for i, s := range segments {
			if isVariable(s) {
				shape[i] = "{}"
			} else {
				shape[i] = s
			}
		}
		shapeKey := strings.Join(shape, "/")
		if prev, ok := shapes[shapeKey]; ok && prev != path {
			return nil, fmt.Errorf("ambiguous path templates %s and %s", prev, path)
		}
		shapes[shapeKey] = path
		item, e := object(paths[path], "path item")
		if e != nil {
			return nil, e
		}
		if e = allowed(item, "summary description parameters get put post delete options head patch trace"); e != nil {
			return nil, e
		}
		inherited, e := compiler.parameters(item["parameters"])
		if e != nil {
			return nil, e
		}
		for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
			v, ok := item[method]
			if !ok {
				continue
			}
			op, e := object(v, "operation")
			if e != nil {
				return nil, e
			}
			if e = allowed(op, "operationId summary description tags parameters requestBody responses deprecated externalDocs security"); e != nil {
				return nil, e
			}
			if e = emptySecurity(op); e != nil {
				return nil, e
			}
			p, e := compiler.parameters(op["parameters"])
			if e != nil {
				return nil, e
			}
			params := append(append([]restParameter(nil), inherited...), p...)
			seen := map[string]bool{}
			for _, param := range params {
				k := param.In + ":" + param.Name
				if seen[k] {
					return nil, fmt.Errorf("duplicate parameter %s", k)
				}
				seen[k] = true
			}
			for _, s := range segments {
				if isVariable(s) {
					name := s[1 : len(s)-1]
					if !seen["path:"+name] {
						return nil, fmt.Errorf("missing path parameter %s", name)
					}
				}
			}
			for _, p := range params {
				if p.In == "path" && !contains(segments, "{"+p.Name+"}") {
					return nil, fmt.Errorf("unused path parameter %s", p.Name)
				}
			}
			id, ok := op["operationId"].(string)
			if raw, exists := op["operationId"]; exists && (!ok || raw == "") {
				return nil, fmt.Errorf("operationId must be nonempty string")
			}
			if !ok {
				id = strings.ToUpper(method) + " " + path
			}
			if ids[id] {
				return nil, fmt.Errorf("duplicate operation ID %q", id)
			}
			ids[id] = true
			compiled := restOperation{ID: id, Method: strings.ToUpper(method), Template: path, Segments: segments, Parameters: params}
			if body, ok := op["requestBody"]; ok {
				b, e := object(body, "requestBody")
				if e != nil {
					return nil, e
				}
				if e = allowed(b, "description required content"); e != nil {
					return nil, e
				}
				compiled.BodyRequired, e = boolProperty(b, "required", false)
				if e != nil {
					return nil, e
				}
				content, e := object(b["content"], "request body content")
				if e != nil {
					return nil, e
				}
				if len(content) != 1 {
					return nil, fmt.Errorf("only application/json request bodies supported")
				}
				media, e := object(content["application/json"], "JSON media type")
				if e != nil {
					return nil, e
				}
				if e = allowed(media, "schema example examples"); e != nil {
					return nil, e
				}
				compiled.Body, e = compiler.compile(media["schema"], map[string]bool{}, 0)
				if e != nil {
					return nil, e
				}
			}
			for _, existing := range out.operations {
				if existing.Method == compiled.Method && overlappingTemplates(existing.Segments, compiled.Segments) {
					return nil, fmt.Errorf("overlapping templated routes %s and %s", existing.Template, compiled.Template)
				}
			}
			out.operations = append(out.operations, compiled)
		}
	}
	if len(out.operations) == 0 {
		return nil, fmt.Errorf("schema has no operations")
	}
	// Literal segments outrank templates. A remaining specificity tie is rejected on use.
	sort.Slice(out.operations, func(i, j int) bool {
		a, b := out.operations[i], out.operations[j]
		if a.Template == b.Template {
			return a.Method < b.Method
		}
		return a.Template < b.Template
	})
	out.catalog = Catalog{Protocol: "rest", Operations: []Operation{}}
	for _, op := range out.operations {
		out.catalog.Operations = append(out.catalog.Operations, Operation{ID: op.ID, Method: op.Method, Path: op.Template, Signature: digest(op), Contract: restContract(op)})
	}
	sort.Slice(out.catalog.Operations, func(i, j int) bool { return out.catalog.Operations[i].ID < out.catalog.Operations[j].ID })
	out.catalog.Digest = digest(doc)
	return out, nil
}
func emptySecurity(m map[string]any) error {
	if v, ok := m["security"]; ok {
		a, ok := v.([]any)
		if !ok || len(a) != 0 {
			return fmt.Errorf("OpenAPI security requirements are unsupported, configure gateway authentication explicitly")
		}
	}
	return nil
}
func (s *RESTSchema) Digest() string   { return s.catalog.Digest }
func (s *RESTSchema) Catalog() Catalog { return cloneCatalog(s.catalog) }
func NormalizeREST(spec []byte, req *http.Request) (*Request, error) {
	s, e := CompileREST(spec)
	if e != nil {
		return nil, e
	}
	return s.Normalize(req)
}
func (s *RESTSchema) Normalize(req *http.Request) (*Request, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("missing request URL")
	}
	if req.Method != strings.ToUpper(req.Method) {
		return nil, fmt.Errorf("noncanonical HTTP method")
	}
	path := req.URL.Path
	if req.URL.RawPath != "" || strings.Contains(req.URL.EscapedPath(), "%") || strings.ContainsAny(path, "\\%\x00") || !utf8.ValidString(path) {
		return nil, fmt.Errorf("encoded or ambiguous URL path")
	}
	seg, err := templateSegments(path)
	if err != nil {
		return nil, err
	}
	var match *restOperation
	var rank []bool
	for i := range s.operations {
		op := &s.operations[i]
		if op.Method != req.Method || len(op.Segments) != len(seg) {
			continue
		}
		r := make([]bool, len(seg))
		ok := true
		for j, part := range op.Segments {
			if !isVariable(part) {
				r[j] = true
				if part != seg[j] {
					ok = false
					break
				}
			}
		}
		if !ok {
			continue
		}
		cmp := compareSpecificity(r, rank)
		if match == nil || cmp > 0 {
			match = op
			rank = r
		} else if cmp == 0 {
			return nil, fmt.Errorf("ambiguous operation match")
		}
	}
	if match == nil {
		return nil, fmt.Errorf("unknown REST operation")
	}
	out := &Request{Protocol: "rest", OperationID: match.ID, Method: req.Method, PathTemplate: match.Template, Path: map[string]any{}, Query: map[string]any{}}
	query, err := strictQuery(req.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, p := range match.Parameters {
		var raw string
		var present bool
		if p.In == "path" {
			for i, part := range match.Segments {
				if part == "{"+p.Name+"}" {
					raw = seg[i]
					present = true
				}
			}
		} else {
			raw, present = query[p.Name]
			known[p.Name] = true
		}
		if !present {
			if p.Required {
				return nil, fmt.Errorf("missing %s parameter %s", p.In, p.Name)
			}
			continue
		}
		value, e := p.Schema.parseParameter(raw)
		if e != nil {
			return nil, fmt.Errorf("parameter %s: %w", p.Name, e)
		}
		if p.In == "path" {
			out.Path[p.Name] = value
		} else {
			out.Query[p.Name] = value
		}
	}
	for name := range query {
		if !known[name] {
			return nil, fmt.Errorf("unknown query parameter %q", name)
		}
	}
	data, err := readBody(req)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		if match.Body == nil {
			return nil, fmt.Errorf("request body not declared")
		}
		if len(req.Header.Values("Content-Type")) != 1 {
			return nil, fmt.Errorf("one JSON content type required")
		}
		media, params, e := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if e != nil || media != "application/json" || (len(params) > 0 && (len(params) != 1 || strings.ToLower(params["charset"]) != "utf-8")) {
			return nil, fmt.Errorf("unsupported content type")
		}
		value, e := DecodeJSON(data)
		if e != nil {
			return nil, e
		}
		out.Body, e = match.Body.validate(value, 0)
		if e != nil {
			return nil, fmt.Errorf("body: %w", e)
		}
	} else if match.BodyRequired {
		return nil, fmt.Errorf("required body missing")
	}
	return out, nil
}
func compareSpecificity(a, b []bool) int {
	for i := range a {
		if i >= len(b) {
			return 1
		}
		if a[i] != b[i] {
			if a[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}
func strictQuery(raw string) (map[string]string, error) {
	out := map[string]string{}
	if raw == "" {
		return out, nil
	}
	for _, piece := range strings.Split(raw, "&") {
		if piece == "" || strings.Contains(piece, ";") {
			return nil, fmt.Errorf("ambiguous query encoding")
		}
		parts := strings.SplitN(piece, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("query value required")
		}
		k, e := url.QueryUnescape(parts[0])
		if e != nil {
			return nil, e
		}
		v, e := url.QueryUnescape(parts[1])
		if e != nil {
			return nil, e
		}
		if k == "" || !utf8.ValidString(k) || !utf8.ValidString(v) || strings.ContainsAny(k+v, "\x00\\%") {
			return nil, fmt.Errorf("ambiguous query encoding")
		}
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("duplicate query parameter %q", k)
		}
		out[k] = v
	}
	return out, nil
}
func templateSegments(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\%\x00") {
		return nil, fmt.Errorf("invalid path")
	}
	if path == "/" {
		return []string{}, nil
	}
	parts := strings.Split(path[1:], "/")
	names := map[string]bool{}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("noncanonical path")
		}
		if strings.ContainsAny(p, "{}") {
			if !isVariable(p) || strings.ContainsAny(p[1:len(p)-1], "{}") || len(p) <= 2 {
				return nil, fmt.Errorf("partial path templates unsupported")
			}
			if names[p] {
				return nil, fmt.Errorf("duplicate path variable")
			}
			names[p] = true
		}
	}
	return parts, nil
}
func isVariable(s string) bool { return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") }
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

type restCompiler struct {
	definitions map[string]any
	remaining   *int
}

func (c restCompiler) parameters(raw any) ([]restParameter, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("parameters must be array")
	}
	out := []restParameter{}
	for _, v := range arr {
		m, e := object(v, "parameter")
		if e != nil {
			return nil, e
		}
		if e = allowed(m, "name in required schema description deprecated style explode allowReserved"); e != nil {
			return nil, e
		}
		name, ok := m["name"].(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid parameter name")
		}
		in, _ := m["in"].(string)
		if in != "query" && in != "path" {
			return nil, fmt.Errorf("only path/query parameters supported")
		}
		required, e := boolProperty(m, "required", false)
		if e != nil {
			return nil, e
		}
		if in == "path" && !required {
			return nil, fmt.Errorf("path parameter must be required")
		}
		style := m["style"]
		if style != nil && ((in == "query" && style != "form") || (in == "path" && style != "simple")) {
			return nil, fmt.Errorf("unsupported parameter serialization")
		}
		reserved, e := boolProperty(m, "allowReserved", false)
		if e != nil || reserved {
			return nil, fmt.Errorf("allowReserved unsupported")
		}
		if _, e = boolProperty(m, "explode", in == "query"); e != nil {
			return nil, e
		}
		s, e := c.compile(m["schema"], map[string]bool{}, 0)
		if e != nil {
			return nil, e
		}
		if s.Type == "object" || s.Type == "array" || s.Nullable {
			return nil, fmt.Errorf("parameters require nonnullable scalar schemas")
		}
		out = append(out, restParameter{name, in, required, s})
	}
	return out, nil
}
func (c restCompiler) compile(raw any, stack map[string]bool, depth int) (*valueSchema, error) {
	*c.remaining--
	if *c.remaining < 0 {
		return nil, fmt.Errorf("expanded schema node limit exceeded")
	}
	if depth > maxDepth {
		return nil, fmt.Errorf("schema depth exceeded")
	}
	m, e := object(raw, "value schema")
	if e != nil {
		return nil, e
	}
	if ref, ok := m["$ref"]; ok {
		r, ok := ref.(string)
		if !ok || !strings.HasPrefix(r, "#/components/schemas/") || len(m) != 1 {
			return nil, fmt.Errorf("only unadorned local schema references supported")
		}
		name := strings.TrimPrefix(r, "#/components/schemas/")
		if strings.ContainsAny(name, "/~") {
			return nil, fmt.Errorf("escaped references unsupported")
		}
		target, ok := c.definitions[name]
		if !ok {
			return nil, fmt.Errorf("unknown reference %s", r)
		}
		if stack[name] {
			return nil, fmt.Errorf("recursive schema unsupported")
		}
		stack[name] = true
		s, e := c.compile(target, stack, depth+1)
		delete(stack, name)
		return s, e
	}
	if e = allowed(m, "type properties required additionalProperties items enum nullable minimum maximum minLength maxLength minItems maxItems pattern description title example examples deprecated"); e != nil {
		return nil, e
	}
	typ, ok := m["type"].(string)
	if !ok {
		return nil, fmt.Errorf("explicit scalar/object/array type required")
	}
	s := &valueSchema{Type: typ}
	s.Nullable, e = boolProperty(m, "nullable", false)
	if e != nil {
		return nil, e
	}
	if v, ok := m["enum"]; ok {
		a, ok := v.([]any)
		if !ok || len(a) == 0 {
			return nil, fmt.Errorf("enum must be nonempty array")
		}
		s.Enum = a
	}
	for _, pair := range []struct {
		key string
		ptr **json.Number
	}{{"minimum", &s.Min}, {"maximum", &s.Max}} {
		if v, ok := m[pair.key]; ok {
			n, ok := v.(json.Number)
			if !ok {
				return nil, fmt.Errorf("invalid %s", pair.key)
			}
			if _, ok := rational(n); !ok {
				return nil, fmt.Errorf("invalid bound")
			}
			*pair.ptr = &n
		}
	}
	for _, pair := range []struct {
		key string
		ptr **int
	}{{"minLength", &s.MinLength}, {"maxLength", &s.MaxLength}, {"minItems", &s.MinItems}, {"maxItems", &s.MaxItems}} {
		if v, ok := m[pair.key]; ok {
			n, ok := v.(json.Number)
			if !ok {
				return nil, fmt.Errorf("invalid %s", pair.key)
			}
			i, e := strconv.Atoi(string(n))
			if e != nil || i < 0 {
				return nil, fmt.Errorf("invalid size bound")
			}
			*pair.ptr = &i
		}
	}
	if p, ok := m["pattern"]; ok {
		pattern, ok := p.(string)
		if !ok {
			return nil, fmt.Errorf("invalid pattern")
		}
		s.Pattern = pattern
		s.pattern, e = regexp.Compile(pattern)
		if e != nil {
			return nil, e
		}
	}
	switch typ {
	case "object":
		s.Properties = map[string]*valueSchema{}
		if p, ok := m["properties"]; ok {
			props, e := object(p, "properties")
			if e != nil {
				return nil, e
			}
			for _, k := range keys(props) {
				s.Properties[k], e = c.compile(props[k], stack, depth+1)
				if e != nil {
					return nil, e
				}
			}
		}
		if a, ok := m["additionalProperties"]; ok && a != false {
			return nil, fmt.Errorf("open object schemas unsupported")
		}
		if r, ok := m["required"]; ok {
			arr, ok := r.([]any)
			if !ok {
				return nil, fmt.Errorf("required must be array")
			}
			for _, v := range arr {
				k, ok := v.(string)
				if !ok || s.Properties[k] == nil || contains(s.Required, k) {
					return nil, fmt.Errorf("invalid required property")
				}
				s.Required = append(s.Required, k)
			}
		}
	case "array":
		s.Items, e = c.compile(m["items"], stack, depth+1)
		if e != nil {
			return nil, e
		}
	case "string", "boolean", "integer", "number":
	default:
		return nil, fmt.Errorf("unsupported schema type %q", typ)
	}
	if typ != "object" && (m["properties"] != nil || m["required"] != nil || m["additionalProperties"] != nil) {
		return nil, fmt.Errorf("object constraints on nonobject")
	}
	if typ != "array" && (m["items"] != nil || s.MinItems != nil || s.MaxItems != nil) {
		return nil, fmt.Errorf("array constraints on nonarray")
	}
	if typ != "string" && (s.MinLength != nil || s.MaxLength != nil || s.pattern != nil) {
		return nil, fmt.Errorf("string constraints on nonstring")
	}
	if typ != "integer" && typ != "number" && (s.Min != nil || s.Max != nil) {
		return nil, fmt.Errorf("numeric constraints on nonnumber")
	}
	if s.Min != nil && s.Max != nil && compareNumbers(*s.Min, *s.Max) > 0 {
		return nil, fmt.Errorf("inverted numeric bounds")
	}
	if len(s.Enum) > 0 {
		values := s.Enum
		s.Enum = nil
		for _, v := range values {
			if _, e = s.validate(v, depth+1); e != nil {
				return nil, fmt.Errorf("invalid enum: %w", e)
			}
		}
		s.Enum = values
	}
	return s, nil
}

func overlappingTemplates(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	av, bv := false, false
	for i := range a {
		va, vb := isVariable(a[i]), isVariable(b[i])
		av = av || va
		bv = bv || vb
		if !va && !vb && a[i] != b[i] {
			return false
		}
	}
	return av && bv
}
func boolProperty(m map[string]any, key string, fallback bool) (bool, error) {
	v, ok := m[key]
	if !ok {
		return fallback, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", key)
	}
	return b, nil
}
func (s *valueSchema) parseParameter(raw string) (any, error) {
	var v any = raw
	switch s.Type {
	case "integer":
		if !regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`).MatchString(raw) {
			return nil, fmt.Errorf("invalid integer")
		}
		v = json.Number(raw)
	case "number":
		v, err := DecodeJSON([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid numeric parameter")
		}
		n, ok := v.(json.Number)
		if !ok {
			return nil, fmt.Errorf("invalid numeric parameter")
		}
		return s.validate(n, 0)
	case "boolean":
		if raw == "true" {
			v = true
		} else if raw == "false" {
			v = false
		} else {
			return nil, fmt.Errorf("invalid boolean")
		}
	}
	return s.validate(v, 0)
}
func (s *valueSchema) validate(v any, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("value depth exceeded")
	}
	if v == nil {
		if len(s.Enum) > 0 {
			found := false
			for _, x := range s.Enum {
				if x == nil {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("value not in enum")
			}
		}
		if s.Nullable {
			return nil, nil
		}
		return nil, fmt.Errorf("null not allowed")
	}
	if len(s.Enum) > 0 {
		found := false
		for _, x := range s.Enum {
			if digest(x) == digest(v) {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("value not in enum")
		}
	}
	switch s.Type {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected object")
		}
		for _, k := range s.Required {
			if _, ok := m[k]; !ok {
				return nil, fmt.Errorf("required field %s missing", k)
			}
		}
		out := map[string]any{}
		for _, k := range keys(m) {
			child := s.Properties[k]
			if child == nil {
				return nil, fmt.Errorf("unknown field %s", k)
			}
			value, e := child.validate(m[k], depth+1)
			if e != nil {
				return nil, fmt.Errorf("%s: %w", k, e)
			}
			out[k] = value
		}
		return out, nil
	case "array":
		arr, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("expected array")
		}
		if !validLength(len(arr), s.MinItems, s.MaxItems) {
			return nil, fmt.Errorf("array size out of bounds")
		}
		out := make([]any, len(arr))
		for i, x := range arr {
			var e error
			out[i], e = s.Items.validate(x, depth+1)
			if e != nil {
				return nil, e
			}
		}
		return out, nil
	case "string":
		str, ok := v.(string)
		if !ok || !utf8.ValidString(str) {
			return nil, fmt.Errorf("expected string")
		}
		if !validLength(utf8.RuneCountInString(str), s.MinLength, s.MaxLength) || (s.pattern != nil && !s.pattern.MatchString(str)) {
			return nil, fmt.Errorf("string constraint violation")
		}
		return str, nil
	case "boolean":
		if _, ok := v.(bool); !ok {
			return nil, fmt.Errorf("expected boolean")
		}
		return v, nil
	case "integer", "number":
		n, ok := v.(json.Number)
		if !ok {
			return nil, fmt.Errorf("expected number")
		}
		if _, ok := rational(n); !ok {
			return nil, fmt.Errorf("invalid number")
		}
		if s.Min != nil && compareNumbers(n, *s.Min) < 0 || s.Max != nil && compareNumbers(n, *s.Max) > 0 {
			return nil, fmt.Errorf("number outside bounds")
		}
		if s.Type == "integer" {
			i, e := integerValue(n)
			if e != nil {
				return nil, fmt.Errorf("integer must be exact int64")
			}
			return i, nil
		}
		return n, nil
	}
	return nil, fmt.Errorf("unsupported value type")
}
func validLength(n int, min, max *int) bool {
	return (min == nil || n >= *min) && (max == nil || n <= *max)
}

func rational(n json.Number) (*big.Rat, bool) {
	text := string(n)
	if len(text) > 256 {
		return nil, false
	}
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		exponent, err := strconv.Atoi(text[i+1:])
		if err != nil || exponent < -308 || exponent > 308 {
			return nil, false
		}
	}
	return new(big.Rat).SetString(text)
}
func compareNumbers(a, b json.Number) int { x, _ := rational(a); y, _ := rational(b); return x.Cmp(y) }

func validateRESTReferences(value any, definitions map[string]any, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("document reference depth exceeded")
	}
	switch x := value.(type) {
	case map[string]any:
		if v, ok := x["$ref"]; ok {
			ref, ok := v.(string)
			if !ok || !strings.HasPrefix(ref, "#/components/schemas/") {
				return fmt.Errorf("unsupported reference")
			}
			name := strings.TrimPrefix(ref, "#/components/schemas/")
			if _, ok := definitions[name]; !ok {
				return fmt.Errorf("unknown reference %s", ref)
			}
		}
		for _, k := range keys(x) {
			if err := validateRESTReferences(x[k], definitions, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, v := range x {
			if err := validateRESTReferences(v, definitions, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
