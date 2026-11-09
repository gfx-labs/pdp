package schema

import (
	"encoding/json"
	"sort"

	"github.com/vektah/gqlparser/v2/ast"
)

func canonicalContract(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func restContract(operation restOperation) json.RawMessage {
	type parameter struct {
		Name     string       `json:"name"`
		In       string       `json:"in"`
		Required bool         `json:"required"`
		Schema   *valueSchema `json:"schema"`
	}
	parameters := make([]parameter, 0, len(operation.Parameters))
	for _, p := range operation.Parameters {
		parameters = append(parameters, parameter{Name: p.Name, In: p.In, Required: p.Required, Schema: p.Schema})
	}
	sort.Slice(parameters, func(i, j int) bool {
		if parameters[i].In == parameters[j].In {
			return parameters[i].Name < parameters[j].Name
		}
		return parameters[i].In < parameters[j].In
	})
	var body any
	if operation.Body != nil {
		body = map[string]any{"required": operation.BodyRequired, "content_type": "application/json", "schema": operation.Body}
	}
	return canonicalContract(map[string]any{"parameters": parameters, "body": body, "closed_objects": true})
}

func graphQLDefault(value *ast.Value) any {
	if value == nil {
		return nil
	}
	return value.String()
}

func graphQLFieldContract(field *ast.FieldDefinition) map[string]any {
	arguments := map[string]any{}
	for _, argument := range field.Arguments {
		arguments[argument.Name] = map[string]any{"type": argument.Type.String(), "default": graphQLDefault(argument.DefaultValue), "directives": directiveSignature(argument.Directives)}
	}
	return map[string]any{"type": field.Type.String(), "arguments": arguments, "default": graphQLDefault(field.DefaultValue), "directives": directiveSignature(field.Directives)}
}

func graphQLDefinitionContract(definition *ast.Definition) any {
	if definition == nil {
		return nil
	}
	fields := map[string]any{}
	for _, field := range definition.Fields {
		fields[field.Name] = graphQLFieldContract(field)
	}
	enums := map[string]any{}
	for _, value := range definition.EnumValues {
		enums[value.Name] = directiveSignature(value.Directives)
	}
	unions := append([]string{}, definition.Types...)
	interfaces := append([]string{}, definition.Interfaces...)
	sort.Strings(unions)
	sort.Strings(interfaces)
	return map[string]any{"name": definition.Name, "kind": definition.Kind, "fields": fields, "enum_values": enums, "union_members": unions, "interfaces": interfaces, "directives": directiveSignature(definition.Directives)}
}

func (s *GraphQLSchema) graphQLContract(field *ast.FieldDefinition) json.RawMessage {
	inputs := map[string]any{}
	for name := range s.inputDependencies(field) {
		inputs[name] = graphQLDefinitionContract(s.schema.Types[name])
	}
	return canonicalContract(map[string]any{
		"arguments":  graphQLFieldContract(field)["arguments"],
		"inputs":     inputs,
		"return":     map[string]any{"type": field.Type.String(), "definition": graphQLDefinitionContract(s.schema.Types[field.Type.Name()])},
		"directives": directiveSignature(field.Directives),
	})
}
