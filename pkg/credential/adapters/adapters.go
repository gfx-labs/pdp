// Package adapters contains administrator-owned credential adapter source.
package adapters

import _ "embed"

//go:embed static.star
var Static string

//go:embed github_app.star
var GitHubApp string

//go:embed oauth_client_credentials.star
var OAuthClientCredentials string

//go:embed oauth_refresh.star
var OAuthRefresh string

//go:embed linear_client_credentials.star
var LinearClientCredentials string

//go:embed linear_refresh.star
var LinearRefresh string
