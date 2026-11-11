package credential

import (
	"context"
	"errors"
	"time"

	"go.starlark.net/starlark"
)

var builtinNames = map[string]bool{"secret": true, "parameter": true, "static": true, "oauth_client_credentials": true, "oauth_refresh": true, "linear_client_credentials": true, "linear_refresh": true, "github_installation": true, "jwt_rs256": true}

type secretHandle struct {
	name      string
	value     []byte
	owner     *execution
	expiresAt time.Time
}

func (*secretHandle) String() string        { return "<opaque secret>" }
func (*secretHandle) Type() string          { return "secret_handle" }
func (*secretHandle) Freeze()               {}
func (*secretHandle) Truth() starlark.Bool  { return true }
func (*secretHandle) Hash() (uint32, error) { return 0, failure(CodeInvalid) }

type resultValue struct {
	result Result
	owner  *execution
}

func (*resultValue) String() string        { return "<credential result>" }
func (*resultValue) Type() string          { return "credential_result" }
func (*resultValue) Freeze()               {}
func (*resultValue) Truth() starlark.Bool  { return true }
func (*resultValue) Hash() (uint32, error) { return 0, failure(CodeInvalid) }

type execution struct {
	manager     *Manager
	ctx         context.Context
	request     Request
	binding     BindingConfig
	provider    ProviderConfig
	active      bool
	nativeError error
	handles     []*secretHandle
}

func (m *Manager) execute(ctx context.Context, r Request) (Result, error) {
	e := &execution{manager: m, ctx: ctx, request: r, binding: m.cfg.Bindings[r.Binding], provider: m.cfg.Providers[r.Provider]}
	defer func() {
		for _, h := range e.handles {
			clear(h.value)
		}
	}()
	thread := &starlark.Thread{Name: "credential", Print: func(*starlark.Thread, string) {}}
	thread.SetMaxExecutionSteps(m.cfg.Limits.MaxSteps)
	stop := context.AfterFunc(ctx, func() { thread.Cancel("credential canceled") })
	defer stop()
	pre := e.builtins()
	globals, err := m.programs[r.Provider].Init(thread, pre)
	if err != nil {
		return Result{}, e.sanitize(err, thread)
	}
	callable, ok := globals["acquire"].(starlark.Callable)
	if !ok {
		return Result{}, failure(CodeInvalid)
	}
	input := starlark.NewDict(3)
	_ = input.SetKey(starlark.String("provider"), starlark.String(r.Provider))
	_ = input.SetKey(starlark.String("binding"), starlark.String(r.Binding))
	scopes := make(starlark.Tuple, len(r.Scopes))
	for i, s := range r.Scopes {
		scopes[i] = starlark.String(s)
	}
	_ = input.SetKey(starlark.String("scopes"), scopes)
	input.Freeze()
	e.active = true
	value, err := starlark.Call(thread, callable, starlark.Tuple{input}, nil)
	if err != nil {
		return Result{}, e.sanitize(err, thread)
	}
	if ctx.Err() != nil {
		return Result{}, failure(CodeCanceled)
	}
	result, ok := value.(*resultValue)
	if !ok || result.owner != e {
		return Result{}, failure(CodeInvalid)
	}
	out := result.result
	if !validValue(out.token, m.cfg.Limits.MaxOutputBytes) || len(out.token)+len(out.username)+len(out.header) > m.cfg.Limits.MaxOutputBytes || !time.Now().Add(m.cfg.Limits.ExpiryMargin).Before(out.ExpiresAt) {
		return Result{}, failure(CodeUnavailable)
	}
	return out, nil
}
func (e *execution) sanitize(_ error, t *starlark.Thread) error {
	if e.ctx.Err() != nil {
		return failure(CodeCanceled)
	}
	if e.nativeError != nil {
		return e.nativeError
	}
	if t.ExecutionSteps() >= e.manager.cfg.Limits.MaxSteps {
		return failure(CodeLimited)
	}
	return failure(CodeUnavailable)
}
func (e *execution) builtins() starlark.StringDict {
	funcs := map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){"secret": e.secret, "parameter": e.parameter, "static": e.static, "oauth_client_credentials": e.oauth, "oauth_refresh": e.oauth, "linear_client_credentials": e.oauth, "linear_refresh": e.oauth, "github_installation": e.github, "jwt_rs256": e.jwt}
	out := make(starlark.StringDict, len(funcs))
	for name, f := range funcs {
		out[name] = starlark.NewBuiltin(name, func(t *starlark.Thread, b *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
			if !e.active || e.ctx.Err() != nil {
				return nil, failure(CodeUnavailable)
			}
			v, err := f(t, b, a, k)
			if err != nil {
				var safe *Error
				if errors.As(err, &safe) {
					e.nativeError = failure(safe.Code)
				} else {
					e.nativeError = failure(CodeInvalid)
				}
				return nil, e.nativeError
			}
			return v, nil
		})
	}
	return out
}
func (e *execution) secret(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kw, "name", &name); err != nil {
		return nil, err
	}
	if _, ok := e.binding.Secrets[name]; !ok {
		return nil, failure(CodeInvalid)
	}
	h := &secretHandle{name: name, owner: e}
	e.handles = append(e.handles, h)
	return h, nil
}
func (e *execution) parameter(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kw, "name", &name); err != nil {
		return nil, err
	}
	p, ok := e.binding.Parameters[name]
	if !ok {
		return nil, failure(CodeInvalid)
	}
	return starlark.String(p), nil
}
func (e *execution) material(h *secretHandle) ([]byte, error) {
	if h == nil || h.owner != e {
		return nil, failure(CodeInvalid)
	}
	if h.value != nil {
		return h.value, nil
	}
	s, ok := e.binding.Secrets[h.name]
	if !ok {
		return nil, failure(CodeInvalid)
	}
	value, err := readSecret(s, e.manager.cfg.CredentialsDirectory, 65536)
	if err != nil {
		return nil, err
	}
	h.value = value
	return value, nil
}
func (e *execution) static(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kw []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	kind := "bearer"
	username := ""
	header := ""
	ttl := 300
	if err := starlark.UnpackArgs(b.Name(), args, kw, "secret", &value, "kind?", &kind, "username?", &username, "header_name?", &header, "ttl_seconds?", &ttl); err != nil {
		return nil, err
	}
	h, ok := value.(*secretHandle)
	if !ok {
		return nil, failure(CodeInvalid)
	}
	raw, err := e.material(h)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 || ttl > 86400 {
		return nil, failure(CodeInvalid)
	}
	r := Result{Kind: Kind(kind), token: string(raw), username: username, header: header, ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second)}
	if !h.expiresAt.IsZero() && h.expiresAt.Before(r.ExpiresAt) {
		r.ExpiresAt = h.expiresAt
	}
	switch r.Kind {
	case Bearer:
	case Basic:
		if !validValue(username, 1024) {
			return nil, failure(CodeInvalid)
		}
	case Header:
		if !ValidHeader(header) {
			return nil, failure(CodeInvalid)
		}
	default:
		return nil, failure(CodeInvalid)
	}
	return &resultValue{result: r, owner: e}, nil
}
