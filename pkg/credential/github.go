package credential

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"go.starlark.net/starlark"
)

func (e *execution) signJWT(handle *secretHandle, issuer string) ([]byte, error) {
	if !validValue(issuer, 256) {
		return nil, failure(CodeInvalid)
	}
	raw, err := e.material(handle)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 {
		return nil, failure(CodeUnavailable)
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
		return nil, failure(CodeUnavailable)
	}
	if key.Validate() != nil {
		return nil, failure(CodeUnavailable)
	}
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": issuer})
	encoding := base64.RawURLEncoding
	message := encoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + encoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return nil, failure(CodeUnavailable)
	}
	return []byte(message + "." + encoding.EncodeToString(signature)), nil
}
func (e *execution) jwt(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var issuer string
	if err := starlark.UnpackArgs(b.Name(), args, kw, "key", &value, "issuer", &issuer); err != nil {
		return nil, err
	}
	handle, ok := value.(*secretHandle)
	if !ok {
		return nil, failure(CodeInvalid)
	}
	signed, err := e.signJWT(handle, issuer)
	if err != nil {
		return nil, err
	}
	h := &secretHandle{owner: e, value: signed, expiresAt: time.Now().Add(8 * time.Minute)}
	e.handles = append(e.handles, h)
	return h, nil
}
func (e *execution) github(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var endpoint string
	var value starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kw, "endpoint", &endpoint, "key", &value); err != nil {
		return nil, err
	}
	handle, ok := value.(*secretHandle)
	if !ok || e.binding.GitHub == nil || !scopesEqual(e.request.Scopes, e.binding.Scopes) {
		return nil, failure(CodeInvalid)
	}
	g := e.binding.GitHub
	jwt, err := e.signJWT(handle, g.AppID)
	if err != nil {
		return nil, err
	}
	defer clear(jwt)
	body, _ := json.Marshal(struct {
		RepositoryIDs []int64           `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}{g.RepositoryIDs, g.Permissions})
	headers := make(http.Header)
	headers.Set("Accept", "application/vnd.github+json")
	headers.Set("Authorization", "Bearer "+string(jwt))
	headers.Set("X-GitHub-Api-Version", "2026-03-10")
	raw, err := e.post(endpoint, "application/json", body, headers)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var response struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			ID int64 `json:"id"`
		} `json:"repositories"`
	}
	if err := decodeResponse(raw, &response); err != nil {
		return nil, err
	}
	if !validValue(response.Token, e.manager.cfg.Limits.MaxOutputBytes) || !time.Now().Add(e.manager.cfg.Limits.ExpiryMargin).Before(response.ExpiresAt) || response.ExpiresAt.After(time.Now().Add(2*time.Hour)) {
		return nil, failure(CodeUnavailable)
	}
	if len(response.Permissions) == 0 {
		return nil, failure(CodeUnavailable)
	}
	for permission, level := range response.Permissions {
		expected, ok := g.Permissions[permission]
		// GitHub adds implicit read-only repository metadata permission.
		if permission == "metadata" && level == "read" && !ok {
			continue
		}
		if !ok || (level != "read" && level != "write") || (expected == "read" && level != "read") {
			return nil, failure(CodeUnavailable)
		}
	}
	for permission, level := range g.Permissions {
		if response.Permissions[permission] != level {
			return nil, failure(CodeUnavailable)
		}
	}
	if response.Repositories != nil {
		allowed := map[int64]bool{}
		for _, id := range g.RepositoryIDs {
			allowed[id] = true
		}
		for _, repo := range response.Repositories {
			if !allowed[repo.ID] {
				return nil, failure(CodeUnavailable)
			}
		}
	}
	return &resultValue{owner: e, result: Result{Kind: Bearer, token: response.Token, ExpiresAt: response.ExpiresAt}}, nil
}
