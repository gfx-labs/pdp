package config

import (
	"github.com/gfx-labs/pdp/internal/policy"
	"github.com/gfx-labs/pdp/internal/schema"
)

const reviewedGitHubDigest = "sha256:e5144f87c069a92de5d96588a6b4b4c8614f1f88c9f52b012a7dd63704a0ca89"
const reviewedLinearDigest = "sha256:45be35e9a86ff65c6558a58ea67eebd69d2ee75166b0f4da1385aa5b856aec68"

// Reviewed mappings are an explicit finite set pinned to the reviewed provider
// projections in internal/schema/testdata. Updating a projection requires review
// of this digest, not automatic approval of its newly imported catalog.
func addProfiles(c *Config, catalogs map[string]schema.Catalog) {
	github := map[string]policy.Classification{
		"repos/get":             policy.ReadOperation,
		"issues/get":            policy.ReadOperation,
		"issues/list-comments":  policy.ReadOperation,
		"issues/create-comment": policy.WriteOperation,
	}
	linear := map[string]policy.Classification{
		"Query.issue":            policy.ReadOperation,
		"Issue.id":               policy.ReadOperation,
		"Issue.identifier":       policy.ReadOperation,
		"Issue.title":            policy.ReadOperation,
		"Issue.description":      policy.ReadOperation,
		"Mutation.commentCreate": policy.WriteOperation,
		"CommentPayload.success": policy.ReadOperation,
		"CommentPayload.comment": policy.ReadOperation,
		"Comment.id":             policy.ReadOperation,
		"Comment.body":           policy.ReadOperation,
	}
	known := map[string]bool{}
	for _, op := range c.Policy.Operations {
		known[op.Provider+"\x00"+op.ID] = true
	}
	for _, route := range c.Routes {
		catalog, ok := catalogs[route.Schema]
		if !ok || (route.Provider == "github" && catalog.Digest != reviewedGitHubDigest) || (route.Provider == "linear" && catalog.Digest != reviewedLinearDigest) {
			continue
		}
		definitions := github
		if route.Provider == "linear" {
			definitions = linear
		}
		for _, entry := range catalog.Operations {
			classification, reviewed := definitions[entry.ID]
			if !reviewed || known[route.Provider+"\x00"+entry.ID] {
				continue
			}
			op := policy.Operation{ID: entry.ID, Provider: route.Provider, Classification: classification, Reviewed: true, SchemaDigest: catalog.Digest}
			if route.Provider == "github" {
				op.Resources = []policy.ResourceSelector{{Type: "repository", Source: "path", Components: [][]string{{"owner"}, {"repo"}}}}
			}
			switch route.Provider + "/" + entry.ID {
			case "linear/Query.issue":
				op.Resources = []policy.ResourceSelector{{Type: "issue", Source: "graphql", Field: entry.ID, Path: []string{"id"}}}
			case "linear/Mutation.commentCreate":
				op.Resources = []policy.ResourceSelector{{Type: "issue", Source: "graphql", Field: entry.ID, Path: []string{"input", "issueId"}}}
				op.Constraints.Objects = []policy.ObjectConstraint{{Source: "graphql", Field: entry.ID, Path: []string{"input"}, AllowedKeys: []string{"issueId", "body"}, RequiredStringKeys: []string{"issueId", "body"}}}
			}
			c.Policy.Operations = append(c.Policy.Operations, op)
		}
	}
}
