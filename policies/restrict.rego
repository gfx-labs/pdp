package pdp.custom

import rego.v1

# Example constraint only. Loading this module never grants access.
deny contains "dangerous query option is forbidden" if {
	input.schema_digest != ""
	input.http.normalized_query.dangerous == true
}

deny contains "dangerous query option is forbidden" if {
	input.schema_digest == ""
	"true" in object.get(object.get(input.http, "query", {}), "dangerous", [])
}
