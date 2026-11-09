package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
	"github.com/vektah/gqlparser/v2/validator/rules"
)

const MaxFieldOccurrences = 4096
const MaxQueryTokens = 32768

type GraphQLSchema struct {
	schema  *ast.Schema
	catalog Catalog
}

func CompileGraphQL(sdl []byte) (*GraphQLSchema, error) {
	if len(sdl) == 0 || len(sdl) > MaxDocumentBytes || !utf8.Valid(sdl) {
		return nil, fmt.Errorf("invalid GraphQL schema size or UTF-8")
	}
	if err := validGraphQLUnicode(string(sdl), 200000); err != nil {
		return nil, err
	}
	doc, e := parser.ParseSchemasWithLimit(200000, validator.Prelude, &ast.Source{Name: "schema.graphql", Input: string(sdl)})
	if e != nil {
		return nil, e
	}
	for _, d := range doc.Directives {
		if d.Position != nil && !d.Position.Src.BuiltIn && strings.Contains(" include skip deprecated specifiedBy ", " "+d.Name+" ") {
			return nil, fmt.Errorf("builtin directive redefinition unsupported")
		}
	}
	schema, e := validator.ValidateSchemaDocument(doc)
	if e != nil {
		return nil, e
	}
	if len(schema.SchemaDirectives) > 0 {
		return nil, fmt.Errorf("schema directives unsupported")
	}
	out := &GraphQLSchema{schema: schema, catalog: Catalog{Protocol: "graphql", Operations: []Operation{}}}
	canonical := map[string]any{}
	names := make([]string, 0, len(schema.Types))
	for name := range schema.Types {
		if !strings.HasPrefix(name, "__") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		def := schema.Types[name]
		if err := supportedSchemaDirectives(def.Directives); err != nil {
			return nil, err
		}
		fields := map[string]any{}
		for _, f := range def.Fields {
			if err := supportedSchemaDirectives(f.Directives); err != nil {
				return nil, err
			}
			for _, a := range f.Arguments {
				if err := supportedSchemaDirectives(a.Directives); err != nil {
					return nil, err
				}
			}
			fields[f.Name] = fieldSignature(f)
		}
		enums := map[string]any{}
		for _, v := range def.EnumValues {
			if err := supportedSchemaDirectives(v.Directives); err != nil {
				return nil, err
			}
			enums[v.Name] = directiveSignature(v.Directives)
		}
		unions := append([]string(nil), def.Types...)
		sort.Strings(unions)
		interfaces := append([]string(nil), def.Interfaces...)
		sort.Strings(interfaces)
		canonical[name] = map[string]any{"kind": def.Kind, "fields": fields, "enums": enums, "unions": unions, "interfaces": interfaces, "directives": directiveSignature(def.Directives)}
		if def.Kind != ast.Object && def.Kind != ast.Interface {
			continue
		}
		for _, f := range def.Fields {
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			coordinate := name + "." + f.Name
			kind := "field"
			if def == schema.Query {
				kind = "query"
			}
			if def == schema.Mutation {
				kind = "mutation"
			}
			if def == schema.Subscription {
				kind = "subscription"
			}
			sig := map[string]any{"field": fieldSignature(f), "inputs": out.inputDependencies(f)}
			out.catalog.Operations = append(out.catalog.Operations, Operation{ID: coordinate, Coordinate: coordinate, Type: kind, Signature: digest(sig), Contract: out.graphQLContract(f)})
		}
	}
	root := func(d *ast.Definition) string {
		if d == nil {
			return ""
		}
		return d.Name
	}
	canonical["$roots"] = []string{root(schema.Query), root(schema.Mutation), root(schema.Subscription)}
	directives := map[string]any{}
	for name, d := range schema.Directives {
		if err := supportedSchemaDirectives(d.Directives); err != nil {
			return nil, err
		}
		args := map[string]any{}
		for _, a := range d.Arguments {
			args[a.Name] = []string{a.Type.String(), a.DefaultValue.String()}
		}
		locations := append([]ast.DirectiveLocation(nil), d.Locations...)
		sort.Slice(locations, func(i, j int) bool { return locations[i] < locations[j] })
		directives[name] = map[string]any{"arguments": args, "locations": locations, "repeatable": d.IsRepeatable}
	}
	canonical["$directives"] = directives
	sort.Slice(out.catalog.Operations, func(i, j int) bool { return out.catalog.Operations[i].ID < out.catalog.Operations[j].ID })
	out.catalog.Digest = digest(canonical)
	return out, nil
}

func supportedSchemaDirectives(ds ast.DirectiveList) error {
	for _, d := range ds {
		if d.Name != "deprecated" && d.Name != "specifiedBy" {
			return fmt.Errorf("unsupported applied schema directive @%s", d.Name)
		}
	}
	return nil
}
func directiveSignature(ds ast.DirectiveList) []string {
	out := []string{}
	for _, d := range ds {
		args := map[string]string{}
		for _, a := range d.Arguments {
			args[a.Name] = a.Value.String()
		}
		b, _ := json.Marshal(args)
		out = append(out, d.Name+string(b))
	}
	sort.Strings(out)
	return out
}
func fieldSignature(f *ast.FieldDefinition) any {
	args := map[string]any{}
	for _, a := range f.Arguments {
		args[a.Name] = []any{a.Type.String(), a.DefaultValue.String(), directiveSignature(a.Directives)}
	}
	return map[string]any{"type": f.Type.String(), "arguments": args, "default": f.DefaultValue.String(), "directives": directiveSignature(f.Directives)}
}
func (s *GraphQLSchema) inputDependencies(f *ast.FieldDefinition) map[string]any {
	out := map[string]any{}
	var visit func(*ast.Type)
	visit = func(t *ast.Type) {
		name := t.Name()
		if _, ok := out[name]; ok {
			return
		}
		d := s.schema.Types[name]
		if d == nil {
			return
		}
		out[name] = nil
		fields := map[string]any{}
		for _, field := range d.Fields {
			fields[field.Name] = fieldSignature(field)
			visit(field.Type)
		}
		enums := map[string]any{}
		for _, v := range d.EnumValues {
			enums[v.Name] = directiveSignature(v.Directives)
		}
		out[name] = map[string]any{"kind": d.Kind, "fields": fields, "enum": enums}
	}
	for _, a := range f.Arguments {
		visit(a.Type)
	}
	return out
}
func (s *GraphQLSchema) Digest() string   { return s.catalog.Digest }
func (s *GraphQLSchema) Catalog() Catalog { return cloneCatalog(s.catalog) }

func (s *GraphQLSchema) NormalizeHTTP(req *http.Request) (*Request, error) {
	if req == nil || req.Method != "POST" || req.URL == nil || req.URL.RawQuery != "" {
		return nil, fmt.Errorf("GraphQL requires POST without URL query")
	}
	media, params, e := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if len(req.Header.Values("Content-Type")) != 1 || e != nil || media != "application/json" || (len(params) > 0 && (len(params) != 1 || strings.ToLower(params["charset"]) != "utf-8")) {
		return nil, fmt.Errorf("GraphQL requires JSON content type")
	}
	data, e := readBody(req)
	if e != nil {
		return nil, e
	}
	value, e := DecodeJSON(data)
	if e != nil {
		return nil, e
	}
	obj, e := object(value, "GraphQL envelope (batching unsupported)")
	if e != nil {
		return nil, e
	}
	if e = allowed(obj, "query operationName variables"); e != nil {
		return nil, e
	}
	query, ok := obj["query"].(string)
	if !ok || query == "" {
		return nil, fmt.Errorf("query string required")
	}
	name := ""
	if v, ok := obj["operationName"]; ok && v != nil {
		var good bool
		name, good = v.(string)
		if !good {
			return nil, fmt.Errorf("operationName must be string")
		}
	}
	variables := map[string]any{}
	if v, ok := obj["variables"]; ok && v != nil {
		variables, e = object(v, "variables")
		if e != nil {
			return nil, e
		}
	}
	return s.Normalize(query, name, variables)
}
func (s *GraphQLSchema) Normalize(query, operationName string, variables map[string]any) (*Request, error) {
	if len(query) == 0 || len(query) > MaxBodyBytes || !utf8.ValidString(query) {
		return nil, fmt.Errorf("invalid query size or UTF-8")
	}
	if err := validGraphQLUnicode(query, MaxQueryTokens); err != nil {
		return nil, err
	}
	doc, e := parser.ParseQueryWithTokenLimit(&ast.Source{Name: "request.graphql", Input: query}, MaxQueryTokens)
	if e != nil {
		return nil, e
	}
	// Bound expansion before validator recursion, including unselected operations.
	for _, op := range doc.Operations {
		count := 0
		if e = boundSelections(doc, op.SelectionSet, map[string]bool{}, 0, &count); e != nil {
			return nil, e
		}
	}
	for _, fragment := range doc.Fragments {
		count := 0
		if e = boundSelections(doc, fragment.SelectionSet, map[string]bool{fragment.Name: true}, 0, &count); e != nil {
			return nil, e
		}
	}
	if errs := validator.ValidateWithRules(s.schema, doc, rules.NewDefaultRules()); len(errs) > 0 {
		return nil, errs
	}
	var op *ast.OperationDefinition
	if operationName == "" {
		if len(doc.Operations) != 1 {
			return nil, fmt.Errorf("operationName required for multiple operations")
		}
		op = doc.Operations[0]
	} else {
		op = doc.Operations.ForName(operationName)
		if op == nil {
			return nil, fmt.Errorf("unknown operationName")
		}
	}
	if op.Operation != ast.Query && op.Operation != ast.Mutation {
		return nil, fmt.Errorf("subscriptions unsupported")
	}
	if len(op.Directives) > 0 {
		return nil, fmt.Errorf("operation directives unsupported")
	}
	for _, f := range doc.Fragments {
		if len(f.VariableDefinition) > 0 || len(f.Directives) > 0 {
			return nil, fmt.Errorf("fragment variables/directives unsupported")
		}
	}
	supplied := map[string]bool{}
	for _, v := range op.VariableDefinitions {
		supplied[v.Variable] = true
		if len(v.Directives) > 0 {
			return nil, fmt.Errorf("variable directives unsupported")
		}
	}
	for name := range variables {
		if !supplied[name] {
			return nil, fmt.Errorf("unknown variable %s", name)
		}
	}
	coerced := map[string]any{}
	budget := &valueBudget{nodes: 65536, bytes: MaxDocumentBytes}
	for _, v := range op.VariableDefinitions {
		value, present := variables[v.Variable]
		if !present && v.DefaultValue != nil {
			value, e = v.DefaultValue.Value(nil)
			if e != nil {
				return nil, e
			}
			present = true
		}
		if !present {
			if v.Type.NonNull {
				return nil, fmt.Errorf("missing variable %s", v.Variable)
			}
			continue
		}
		value, e = s.coerce(v.Type, value, 0, budget)
		if e != nil {
			return nil, fmt.Errorf("variable %s: %w", v.Variable, e)
		}
		coerced[v.Variable] = value
	}
	id := op.Name
	if id == "" {
		id = string(op.Operation)
	}
	out := &Request{Protocol: "graphql", OperationID: id, OperationName: op.Name, OperationType: string(op.Operation), Variables: coerced, Fields: []FieldOccurrence{}}
	if e = s.walk(doc, op.SelectionSet, coerced, nil, &out.Fields, 0, budget); e != nil {
		return nil, e
	}
	return out, nil
}

func validGraphQLUnicode(source string, limit int) error {
	if !strings.Contains(source, `\u`) {
		return nil
	}
	chars := []rune(source)
	lex := lexer.New(&ast.Source{Input: source})
	for count := 0; count <= limit; count++ {
		token, err := lex.ReadToken()
		if err != nil {
			return err
		}
		if token.Kind == lexer.EOF {
			return nil
		}
		if token.Kind == lexer.String {
			raw := string(chars[token.Pos.Start:token.Pos.End])
			if err := validStringSurrogates([]byte(raw), true); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("GraphQL token limit exceeded")
}
func boundSelections(doc *ast.QueryDocument, selection ast.SelectionSet, stack map[string]bool, depth int, count *int) error {
	if depth > maxDepth {
		return fmt.Errorf("GraphQL selection depth exceeded")
	}
	for _, sel := range selection {
		*count++
		if *count > MaxFieldOccurrences {
			return fmt.Errorf("GraphQL expansion limit exceeded")
		}
		switch x := sel.(type) {
		case *ast.Field:
			if e := boundSelections(doc, x.SelectionSet, stack, depth+1, count); e != nil {
				return e
			}
		case *ast.InlineFragment:
			if e := boundSelections(doc, x.SelectionSet, stack, depth+1, count); e != nil {
				return e
			}
		case *ast.FragmentSpread:
			if stack[x.Name] {
				return fmt.Errorf("fragment cycle")
			}
			f := doc.Fragments.ForName(x.Name)
			if f == nil {
				return fmt.Errorf("unknown fragment")
			}
			stack[x.Name] = true
			if e := boundSelections(doc, f.SelectionSet, stack, depth+1, count); e != nil {
				return e
			}
			delete(stack, x.Name)
		default:
			return fmt.Errorf("unknown GraphQL selection")
		}
	}
	return nil
}
func included(ds ast.DirectiveList, vars map[string]any) (bool, error) {
	include := true
	for _, d := range ds {
		if d.Name != "include" && d.Name != "skip" {
			return false, fmt.Errorf("unsupported executable directive @%s", d.Name)
		}
		a := d.Arguments.ForName("if")
		if a == nil {
			return false, fmt.Errorf("directive if missing")
		}
		v, e := a.Value.Value(vars)
		if e != nil {
			return false, e
		}
		b, ok := v.(bool)
		if !ok {
			return false, fmt.Errorf("directive condition must be Boolean")
		}
		if d.Name == "skip" && b || d.Name == "include" && !b {
			include = false
		}
	}
	return include, nil
}
func (s *GraphQLSchema) walk(doc *ast.QueryDocument, selection ast.SelectionSet, vars map[string]any, path []string, out *[]FieldOccurrence, depth int, budget *valueBudget) error {
	if depth > maxDepth {
		return fmt.Errorf("selection depth exceeded")
	}
	for _, sel := range selection {
		switch x := sel.(type) {
		case *ast.Field:
			_, e := included(x.Directives, vars)
			if e != nil {
				return e
			}
			if strings.HasPrefix(x.Name, "__") {
				return fmt.Errorf("introspection fields unsupported")
			}
			if x.Definition == nil || x.ObjectDefinition == nil {
				return fmt.Errorf("unresolved field")
			}
			args := map[string]any{}
			for _, def := range x.Definition.Arguments {
				arg := x.Arguments.ForName(def.Name)
				var value any
				present := false
				if arg != nil {
					if arg.Value.Kind == ast.Variable {
						_, present = vars[arg.Value.Raw]
					} else {
						present = true
					}
					if present {
						value, e = arg.Value.Value(vars)
						if e != nil {
							return e
						}
					}
				}
				if !present && def.DefaultValue != nil {
					value, e = def.DefaultValue.Value(nil)
					if e != nil {
						return e
					}
					present = true
				}
				if !present {
					if def.Type.NonNull {
						return fmt.Errorf("required argument missing")
					}
					continue
				}
				value, e = s.coerce(def.Type, value, 0, budget)
				if e != nil {
					return fmt.Errorf("argument %s: %w", def.Name, e)
				}
				args[def.Name] = value
			}
			alias := x.Alias
			if alias == "" {
				alias = x.Name
			}
			next := append(append([]string(nil), path...), alias)
			for _, name := range next {
				if err := budget.charge(name); err != nil {
					return err
				}
			}
			// Conditional branches remain authorization requirements, even when skipped.
			*out = append(*out, FieldOccurrence{Coordinate: x.ObjectDefinition.Name + "." + x.Name, Path: next, Arguments: args})
			if len(*out) > MaxFieldOccurrences {
				return fmt.Errorf("field occurrence limit exceeded")
			}
			if e = s.walk(doc, x.SelectionSet, vars, next, out, depth+1, budget); e != nil {
				return e
			}
		case *ast.FragmentSpread:
			_, e := included(x.Directives, vars)
			if e != nil {
				return e
			}
			f := doc.Fragments.ForName(x.Name)
			if f == nil {
				return fmt.Errorf("unresolved fragment")
			}
			if e = s.walk(doc, f.SelectionSet, vars, path, out, depth+1, budget); e != nil {
				return e
			}
		case *ast.InlineFragment:
			_, e := included(x.Directives, vars)
			if e != nil {
				return e
			}
			if e = s.walk(doc, x.SelectionSet, vars, path, out, depth+1, budget); e != nil {
				return e
			}
		default:
			return fmt.Errorf("unresolved selection")
		}
	}
	return nil
}
func (s *GraphQLSchema) coerce(t *ast.Type, value any, depth int, budget *valueBudget) (any, error) {
	if err := budget.charge(value); err != nil {
		return nil, err
	}
	if depth > maxDepth {
		return nil, fmt.Errorf("input depth exceeded")
	}
	if t.Elem == nil {
		if def := s.schema.Types[t.NamedType]; def != nil && def.Kind == ast.Scalar && !strings.Contains(" String Boolean Int Float ID ", " "+def.Name+" ") {
			return nil, fmt.Errorf("custom input scalar %s unsupported", def.Name)
		}
	}
	if value == nil {
		if t.NonNull {
			return nil, fmt.Errorf("null for nonnull input")
		}
		return nil, nil
	}
	if t.Elem != nil {
		a, ok := value.([]any)
		if !ok {
			a = []any{value}
		}
		out := make([]any, len(a))
		if len(a) > MaxFieldOccurrences {
			return nil, fmt.Errorf("input list too large")
		}
		for i, v := range a {
			var e error
			out[i], e = s.coerce(t.Elem, v, depth+1, budget)
			if e != nil {
				return nil, e
			}
		}
		return out, nil
	}
	def := s.schema.Types[t.NamedType]
	if def == nil {
		return nil, fmt.Errorf("unknown input type")
	}
	switch def.Kind {
	case ast.Enum:
		str, ok := value.(string)
		if !ok || def.EnumValues.ForName(str) == nil {
			return nil, fmt.Errorf("invalid enum %s", def.Name)
		}
		return str, nil
	case ast.InputObject:
		m, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected input object %s", def.Name)
		}
		for name := range m {
			if def.Fields.ForName(name) == nil {
				return nil, fmt.Errorf("unknown input field %s", name)
			}
		}
		out := map[string]any{}
		for _, field := range def.Fields {
			v, present := m[field.Name]
			if !present && field.DefaultValue != nil {
				var e error
				v, e = field.DefaultValue.Value(nil)
				if e != nil {
					return nil, e
				}
				present = true
			}
			if !present {
				if field.Type.NonNull {
					return nil, fmt.Errorf("required input field %s missing", field.Name)
				}
				continue
			}
			if err := budget.charge(field.Name); err != nil {
				return nil, err
			}
			coerced, e := s.coerce(field.Type, v, depth+1, budget)
			if e != nil {
				return nil, e
			}
			out[field.Name] = coerced
		}
		return out, nil
	case ast.Scalar:
		switch def.Name {
		case "String":
			str, ok := value.(string)
			if !ok || !utf8.ValidString(str) {
				return nil, fmt.Errorf("expected String")
			}
			return str, nil
		case "Boolean":
			b, ok := value.(bool)
			if !ok {
				return nil, fmt.Errorf("expected Boolean")
			}
			return b, nil
		case "Int":
			n, e := integerValue(value)
			if e != nil || n < math.MinInt32 || n > math.MaxInt32 {
				return nil, fmt.Errorf("expected signed 32-bit Int")
			}
			return n, nil
		case "Float":
			f, e := floatValue(value)
			if e != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, fmt.Errorf("expected finite Float")
			}
			return f, nil
		case "ID":
			if str, ok := value.(string); ok {
				if !utf8.ValidString(str) {
					return nil, fmt.Errorf("invalid ID")
				}
				return str, nil
			}
			n, e := integerValue(value)
			if e != nil || n < -(1<<53-1) || n > 1<<53-1 {
				return nil, fmt.Errorf("expected string/integer ID")
			}
			return strconv.FormatInt(n, 10), nil
		default:
			return nil, fmt.Errorf("custom input scalar %s unsupported", def.Name)
		}
	}
	return nil, fmt.Errorf("not an input type")
}

type valueBudget struct{ nodes, bytes int }

func (b *valueBudget) charge(value any) error {
	b.nodes--
	if text, ok := value.(string); ok {
		b.bytes -= len(text)
	}
	if b.nodes < 0 || b.bytes < 0 {
		return fmt.Errorf("normalized value expansion limit exceeded")
	}
	return nil
}
func integerValue(value any) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case json.Number:
		r, ok := rational(v)
		if !ok || !r.IsInt() || !r.Num().IsInt64() {
			return 0, fmt.Errorf("not exact integer")
		}
		return r.Num().Int64(), nil
	case float64:
		if !math.IsInf(v, 0) && !math.IsNaN(v) && v == math.Trunc(v) && math.Abs(v) <= 1<<53-1 {
			return int64(v), nil
		}
	}
	return 0, fmt.Errorf("not exact integer")
}
func floatValue(value any) (float64, error) {
	switch v := value.(type) {
	case json.Number:
		return v.Float64()
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	}
	return 0, fmt.Errorf("not number")
}
