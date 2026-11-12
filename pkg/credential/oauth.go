package credential

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
)

func (e *execution) post(alias, contentType string, body []byte, headers http.Header) ([]byte, error) {
	endpoint, ok := e.provider.Endpoints[alias]
	if !ok {
		return nil, failure(CodeInvalid)
	}
	if len(body) > e.manager.cfg.Limits.MaxHTTPResponseBytes {
		return nil, failure(CodeLimited)
	}
	req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, failure(CodeInvalid)
	}
	// NewRequest installs replay support for bytes.Reader by default.
	req.GetBody = nil
	req.Close = true
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", contentType)
	response, err := e.manager.client.Do(req)
	if err != nil {
		return nil, failure(CodeUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, failure(CodeUnavailable)
	}
	if response.ContentLength > int64(e.manager.cfg.Limits.MaxHTTPResponseBytes) {
		return nil, failure(CodeLimited)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(e.manager.cfg.Limits.MaxHTTPResponseBytes)+1))
	if err != nil {
		return nil, failure(CodeUnavailable)
	}
	if len(raw) > e.manager.cfg.Limits.MaxHTTPResponseBytes {
		clear(raw)
		return nil, failure(CodeLimited)
	}
	return raw, nil
}
func decodeResponse(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(out) != nil {
		return failure(CodeUnavailable)
	}
	var tail any
	if dec.Decode(&tail) != io.EOF {
		return failure(CodeUnavailable)
	}
	return nil
}

type oauthResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.Number     `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	Scope        json.RawMessage `json:"scope"`
}

// tokenBody encodes one grant as the form RFC 6749 specifies, or as the JSON
// object some token endpoints take in its place.
func tokenBody(form url.Values, encoding string) (string, []byte) {
	if encoding != "json" {
		return "application/x-www-form-urlencoded", []byte(form.Encode())
	}
	fields := make(map[string]string, len(form))
	for name := range form {
		fields[name] = form.Get(name)
	}
	// A map of strings always marshals.
	raw, _ := json.Marshal(fields)
	return "application/json", raw
}

func scopesEqual(a, b []string) bool {
	ac, ae := canonicalScopes(a)
	bc, be := canonicalScopes(b)
	if ae != nil || be != nil || len(ac) != len(bc) {
		return false
	}
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
func (e *execution) tokenResponse(raw []byte) (oauthResponse, Result, error) {
	var response oauthResponse
	if err := decodeResponse(raw, &response); err != nil {
		return response, Result{}, err
	}
	seconds, err := strconv.ParseInt(string(response.ExpiresIn), 10, 64)
	if err != nil || seconds <= 0 || seconds > 366*86400 || !strings.EqualFold(response.TokenType, "bearer") || !validValue(response.AccessToken, e.manager.cfg.Limits.MaxOutputBytes) {
		return response, Result{}, failure(CodeUnavailable)
	}
	if len(response.Scope) > 0 && string(response.Scope) != "null" {
		var granted []string
		var text string
		if json.Unmarshal(response.Scope, &text) == nil {
			granted = strings.Fields(strings.ReplaceAll(text, ",", " "))
		} else if json.Unmarshal(response.Scope, &granted) != nil {
			return response, Result{}, failure(CodeUnavailable)
		}
		// A provider cannot silently widen or shrink the requested authority.
		if !scopesEqual(granted, e.request.Scopes) {
			return response, Result{}, failure(CodeUnavailable)
		}
	}
	result := Result{Kind: Bearer, token: response.AccessToken, ExpiresAt: time.Now().Add(time.Duration(seconds) * time.Second)}
	if !time.Now().Add(e.manager.cfg.Limits.ExpiryMargin).Before(result.ExpiresAt) {
		return response, Result{}, failure(CodeUnavailable)
	}
	return response, result, nil
}
func (e *execution) oauth(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var endpoint, clientID string
	var value starlark.Value = starlark.None
	authentication, encoding := "body", "form"
	sendScope := false
	if err := starlark.UnpackArgs(b.Name(), args, kw, "endpoint", &endpoint, "client_id", &clientID, "client_secret?", &value, "authentication?", &authentication, "encoding?", &encoding, "send_scope?", &sendScope); err != nil {
		return nil, err
	}
	if !validValue(clientID, 1024) || (authentication != "basic" && authentication != "body") || (encoding != "form" && encoding != "json") {
		return nil, failure(CodeInvalid)
	}
	// A public client has no secret. Only the generic refresh grant accepts
	// that, a JSON body or a scope parameter.
	public := value == starlark.None
	if b.Name() != "oauth_refresh" && (public || encoding != "form" || sendScope) {
		return nil, failure(CodeInvalid)
	}
	if (public && authentication != "body") || (sendScope && len(e.request.Scopes) == 0) {
		return nil, failure(CodeInvalid)
	}
	var secret []byte
	if !public {
		handle, ok := value.(*secretHandle)
		if !ok {
			return nil, failure(CodeInvalid)
		}
		var err error
		if secret, err = e.material(handle); err != nil {
			return nil, err
		}
		if !validValue(string(secret), 65536) {
			return nil, failure(CodeInvalid)
		}
	}
	linear := strings.HasPrefix(b.Name(), "linear_")
	refresh := strings.HasSuffix(b.Name(), "refresh")
	if linear {
		if (!refresh && e.binding.LinearActor != "app") || (refresh && e.binding.LinearActor != "app" && e.binding.LinearActor != "user") || !scopesEqual(e.request.Scopes, e.binding.Scopes) {
			return nil, failure(CodeInvalid)
		}
	}
	if refresh && !scopesEqual(e.request.Scopes, e.binding.Scopes) {
		return nil, failure(CodeInvalid)
	}
	form := url.Values{}
	headers := make(http.Header)
	headers.Set("Accept", "application/json")
	if authentication == "basic" {
		// RFC 6749 encodes each component before applying HTTP Basic.
		req := &http.Request{Header: headers}
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(string(secret)))
	} else {
		form.Set("client_id", clientID)
		if !public {
			form.Set("client_secret", string(secret))
		}
	}
	var previous tokenState
	if refresh {
		path := e.binding.StateFile
		if path == "" {
			return nil, failure(CodeInvalid)
		}
		e.manager.mu.Lock()
		poisoned := e.manager.poisoned[path]
		e.manager.mu.Unlock()
		if poisoned {
			return nil, failure(CodePersistence)
		}
		unlock, err := lockState(e.ctx, path)
		if err != nil {
			return nil, err
		}
		defer unlock()
		previous, err = loadState(path, e.manager.cfg.Limits.MaxHTTPResponseBytes)
		if err != nil {
			return nil, err
		}
		if !scopesEqual(previous.Scopes, e.binding.Scopes) {
			return nil, failure(CodeInvalid)
		}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", previous.RefreshToken)
		if sendScope {
			form.Set("scope", strings.Join(e.request.Scopes, " "))
		}
		contentType, body := tokenBody(form, encoding)
		defer clear(body)
		// Persist intent before the external effect. A lost response or crash must
		// not let another process replay a possibly consumed refresh token.
		previous.Pending = true
		if err := persistState(path, previous, e.manager.cfg.Limits.MaxHTTPResponseBytes); err != nil {
			return nil, err
		}
		raw, err := e.post(endpoint, contentType, body, headers)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		var parsed oauthResponse
		if err := decodeResponse(raw, &parsed); err != nil {
			return nil, err
		}
		response, result, validationErr := e.tokenResponse(raw)
		replacement := response.RefreshToken
		if replacement == "" {
			if linear {
				return nil, failure(CodeUnavailable)
			}
			replacement = previous.RefreshToken
		}
		if !validValue(replacement, e.manager.cfg.Limits.MaxOutputBytes) {
			return nil, failure(CodeUnavailable)
		}
		// Retain a valid replacement even if the new access token is unusable.
		// Recovery then requires administrator reconciliation, never replay.
		next := tokenState{AccessToken: response.AccessToken, RefreshToken: replacement, ExpiresAt: result.ExpiresAt, Scopes: append([]string(nil), e.request.Scopes...), Pending: validationErr != nil}
		if err := persistState(path, next, e.manager.cfg.Limits.MaxHTTPResponseBytes); err != nil {
			e.manager.mu.Lock()
			e.manager.poisoned[path] = true
			e.manager.mu.Unlock()
			return nil, err
		}
		if validationErr != nil {
			return nil, validationErr
		}
		return &resultValue{result: result, owner: e}, nil
	}
	form.Set("grant_type", "client_credentials")
	separator := " "
	if linear {
		separator = ","
	}
	if len(e.request.Scopes) > 0 {
		form.Set("scope", strings.Join(e.request.Scopes, separator))
	} else if linear {
		return nil, failure(CodeInvalid)
	}
	raw, err := e.post(endpoint, "application/x-www-form-urlencoded", []byte(form.Encode()), headers)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	_, result, err := e.tokenResponse(raw)
	if err != nil {
		return nil, err
	}
	return &resultValue{result: result, owner: e}, nil
}
