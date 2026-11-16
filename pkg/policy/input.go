package policy

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/open-policy-agent/opa/v1/ast"
)

// inputValue builds the OPA value a policy reads as input, without a JSON round
// trip. Field names and omission rules must match the json tags on Input, which
// TestInputValueMatchesJSON checks against the encoder.
func inputValue(input Input) (ast.Value, error) {
	b := builder{}
	identity := object{}
	identity.text("id", input.Identity.ID, &b)
	identity.optional("auth_method", input.Identity.AuthMethod, &b)
	identity.optional("spiffe_id", input.Identity.SPIFFEID, &b)
	if input.Identity.UID != nil {
		identity.add("uid", ast.UIntNumberTerm(uint64(*input.Identity.UID)))
	}
	identity.optional("ip", input.Identity.IP, &b)

	destination := object{}
	destination.text("scheme", input.Destination.Scheme, &b)
	destination.text("host", input.Destination.Host, &b)
	destination.add("port", ast.InternedTerm(input.Destination.Port))
	if len(input.Destination.Addresses) > 0 {
		destination.add("addresses", b.texts(input.Destination.Addresses))
	}

	root := object{}
	root.text("version", input.Version, &b)
	root.add("identity", identity.term())
	root.text("protocol", input.Protocol, &b)
	root.add("destination", destination.term())
	root.optional("binding", input.Binding, &b)
	root.optional("plugin", input.Plugin, &b)
	root.optional("schema_digest", input.SchemaDigest, &b)
	if input.HTTP != nil {
		http := object{}
		http.text("method", input.HTTP.Method, &b)
		http.text("path", input.HTTP.Path, &b)
		if len(input.HTTP.Headers) > 0 {
			headers := object{}
			for key, values := range input.HTTP.Headers {
				headers.addKey(b.text(key), b.texts(values))
			}
			http.add("headers", headers.term())
		}
		if len(input.HTTP.PathParams) > 0 {
			params := object{}
			for key, value := range input.HTTP.PathParams {
				params.text(key, value, &b)
			}
			http.add("path_params", params.term())
		}
		if len(input.HTTP.Query) > 0 {
			query := object{}
			for key, values := range input.HTTP.Query {
				query.addKey(b.text(key), b.texts(values))
			}
			http.add("query", query.term())
		}
		if len(input.HTTP.NormalizedQuery) > 0 {
			http.add("normalized_query", b.dynamicObject(input.HTTP.NormalizedQuery))
		}
		if input.HTTP.Body != nil {
			http.add("body", b.dynamic(input.HTTP.Body))
		}
		root.add("http", http.term())
	}
	if len(input.Operations) > 0 {
		operations := make([]*ast.Term, 0, len(input.Operations))
		for _, operation := range input.Operations {
			entry := object{}
			entry.text("id", operation.ID, &b)
			if len(operation.Resources) > 0 {
				resources := make([]*ast.Term, 0, len(operation.Resources))
				for _, resource := range operation.Resources {
					item := object{}
					item.text("type", resource.Type, &b)
					item.text("id", resource.ID, &b)
					resources = append(resources, item.term())
				}
				entry.add("resources", ast.ArrayTerm(resources...))
			}
			operations = append(operations, entry.term())
		}
		root.add("operations", ast.ArrayTerm(operations...))
	}
	if len(input.GraphQL) > 0 {
		fields := make([]*ast.Term, 0, len(input.GraphQL))
		for _, field := range input.GraphQL {
			entry := object{}
			entry.text("coordinate", field.Coordinate, &b)
			// The path and arguments tags have no omitempty: nil encodes as null.
			if field.Path == nil {
				entry.add("path", ast.InternedNullTerm)
			} else {
				entry.add("path", b.texts(field.Path))
			}
			if len(field.ResponsePath) > 0 {
				entry.add("response_path", b.texts(field.ResponsePath))
			}
			entry.optional("parent_type", field.ParentType, &b)
			entry.optional("field", field.Field, &b)
			entry.optional("alias", field.Alias, &b)
			if field.Arguments == nil {
				entry.add("arguments", ast.InternedNullTerm)
			} else {
				entry.add("arguments", b.dynamicObject(field.Arguments))
			}
			fields = append(fields, entry.term())
		}
		root.add("graphql", ast.ArrayTerm(fields...))
	}
	root.optional("operation_type", input.OperationType, &b)
	root.optional("operation_name", input.OperationName, &b)
	if len(input.Variables) > 0 {
		root.add("variables", b.dynamicObject(input.Variables))
	}
	if b.err != nil {
		return nil, b.err
	}
	return root.term().Value, nil
}

type object struct{ items [][2]*ast.Term }

func (o *object) add(key string, value *ast.Term) {
	o.items = append(o.items, ast.Item(ast.InternedTerm(key), value))
}

func (o *object) addKey(key, value *ast.Term) { o.items = append(o.items, ast.Item(key, value)) }

func (o *object) text(key, value string, b *builder) { o.addKey(b.text(key), b.text(value)) }

func (o *object) optional(key, value string, b *builder) {
	if value != "" {
		o.add(key, b.text(value))
	}
}

func (o *object) term() *ast.Term { return ast.ObjectTerm(o.items...) }

// builder keeps the first conversion error so call sites stay linear.
type builder struct{ err error }

// text matches the encoder, which replaces invalid UTF-8 instead of passing it on.
func (b *builder) text(s string) *ast.Term {
	if !utf8.ValidString(s) {
		return b.roundTrip(s)
	}
	return ast.InternedTerm(s)
}

func (b *builder) texts(values []string) *ast.Term {
	terms := make([]*ast.Term, len(values))
	for i, value := range values {
		terms[i] = b.text(value)
	}
	return ast.ArrayTerm(terms...)
}

func (b *builder) dynamicObject(values map[string]any) *ast.Term {
	items := make([][2]*ast.Term, 0, len(values))
	for key, value := range values {
		items = append(items, ast.Item(b.text(key), b.dynamic(value)))
	}
	return ast.ObjectTerm(items...)
}

// dynamic converts request-derived JSON. The gateway's decoders produce only the
// cases listed. Any other Go value takes the encoder's route, so it means what
// its JSON form means or fails the evaluation.
func (b *builder) dynamic(value any) *ast.Term {
	switch typed := value.(type) {
	case nil:
		return ast.InternedNullTerm
	case bool:
		return ast.InternedTerm(typed)
	case string:
		return b.text(typed)
	case json.Number:
		if !json.Valid([]byte(typed)) {
			return b.roundTrip(typed)
		}
		number, err := ast.InterfaceToValue(typed)
		if err != nil {
			return b.fail(err)
		}
		return ast.NewTerm(number)
	case []any:
		terms := make([]*ast.Term, len(typed))
		for i, item := range typed {
			terms[i] = b.dynamic(item)
		}
		return ast.ArrayTerm(terms...)
	case map[string]any:
		return b.dynamicObject(typed)
	default:
		return b.roundTrip(value)
	}
}

func (b *builder) roundTrip(value any) *ast.Term {
	encoded, err := json.Marshal(value)
	if err != nil {
		return b.fail(err)
	}
	var plain any
	if err := decodeJSON(encoded, &plain); err != nil {
		return b.fail(err)
	}
	converted, err := ast.InterfaceToValue(plain)
	if err != nil {
		return b.fail(err)
	}
	return ast.NewTerm(converted)
}

func (b *builder) fail(err error) *ast.Term {
	if b.err == nil {
		b.err = err
	}
	return ast.InternedNullTerm
}
