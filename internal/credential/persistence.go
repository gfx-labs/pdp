package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func readSecret(s SecretSource, dir string, max int) ([]byte, error) {
	path := s.File
	if s.SystemdCredential != "" {
		path = filepath.Join(dir, s.SystemdCredential)
	}
	raw, err := readFile(path, max, false)
	if err != nil {
		return nil, err
	}
	// Mounted text secrets conventionally have one terminal newline.
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	raw = bytes.TrimSuffix(raw, []byte("\r"))
	if len(raw) == 0 {
		return nil, failure(CodeUnavailable)
	}
	return raw, nil
}
func readFile(path string, max int, private bool) ([]byte, error) {
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if private {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, failure(CodeUnavailable)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(max) || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, failure(CodeUnavailable)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, failure(CodeUnavailable)
	}
	return raw, nil
}

// tokenState is durable private state, never policy input or public output.
type tokenState struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	Pending      bool      `json:"recovery_required,omitempty"`
}

func privateParent(path string) bool {
	info, err := os.Stat(filepath.Dir(path))
	return err == nil && info.IsDir() && info.Mode().Perm()&0077 == 0
}
func lockState(ctx context.Context, path string) (func(), error) {
	if !privateParent(path) {
		return nil, failure(CodePersistence)
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, failure(CodePersistence)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, failure(CodePersistence)
	}
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			f.Close()
			return nil, failure(CodeCanceled)
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			f.Close()
			return nil, failure(CodePersistence)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, failure(CodeCanceled)
		case <-timer.C:
		}
	}
}
func loadState(path string, max int) (tokenState, error) {
	var s tokenState
	raw, err := readFile(path, max, true)
	if err != nil {
		return s, failure(CodePersistence)
	}
	defer clear(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || !validValue(s.RefreshToken, max) || s.Pending {
		return tokenState{}, failure(CodePersistence)
	}
	var tail any
	if dec.Decode(&tail) != io.EOF {
		return tokenState{}, failure(CodePersistence)
	}
	if _, err := canonicalScopes(s.Scopes); err != nil {
		return tokenState{}, failure(CodePersistence)
	}
	return s, nil
}

// persistState durably commits the entire pair before callers see the new access
// token. A canceled caller still commits a received rotating refresh token.
func persistState(path string, state tokenState, max int) error {
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > max {
		return failure(CodePersistence)
	}
	defer clear(raw)
	f, err := os.CreateTemp(filepath.Dir(path), ".pdp-credential-*")
	if err != nil {
		return failure(CodePersistence)
	}
	temp := f.Name()
	defer os.Remove(temp)
	if f.Chmod(0600) != nil {
		f.Close()
		return failure(CodePersistence)
	}
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		f.Close()
		return failure(CodePersistence)
	}
	if f.Sync() != nil {
		f.Close()
		return failure(CodePersistence)
	}
	if f.Close() != nil {
		return failure(CodePersistence)
	}
	if os.Rename(temp, path) != nil {
		return failure(CodePersistence)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return failure(CodePersistence)
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		return failure(CodePersistence)
	}
	return nil
}
