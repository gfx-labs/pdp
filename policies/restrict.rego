package pdp.custom

import rego.v1

# Example constraint only. Loading this module never grants access.
deny contains "dangerous query option is forbidden" if {
	"true" in object.get(input.http.query, "dangerous", [])
}
