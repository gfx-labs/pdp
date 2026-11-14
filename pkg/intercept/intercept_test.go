package intercept

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAuthority(t *testing.T, dir string, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test interception CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if isCA {
		template.IsCA, template.KeyUsage = true, x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func verifies(leaf, root *x509.Certificate, host string) bool {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
	return err == nil
}

// A server certificate must not be accepted as the signing CA: clients would
// reject every leaf, and the mistake should fail at startup instead.
func TestLoadRejectsNonCA(t *testing.T) {
	dir := t.TempDir()
	writeAuthority(t, dir, false)
	if _, err := Load(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), nil); err == nil {
		t.Fatal("a certificate without CA usage was loaded as the interception CA")
	}
}

// cert-manager renews the CA by rewriting the mounted files. New leaves must
// come from the new CA, and a cached leaf from the old one must not be served.
func TestRotatedAuthorityReplacesCachedLeaves(t *testing.T) {
	dir := t.TempDir()
	first := writeAuthority(t, dir, true)
	authority, err := Load(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := authority.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !verifies(before.Leaf, first, "api.example.com") || verifies(before.Leaf, first, "other.example.com") {
		t.Fatal("leaf is not valid for exactly the requested host under the loaded CA")
	}
	second := writeAuthority(t, dir, true)
	future := time.Now().Add(time.Hour)
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err = os.Chtimes(filepath.Join(dir, name), future, future); err != nil {
			t.Fatal(err)
		}
	}
	authority.mu.Lock()
	authority.checkedAt = time.Time{} // skip the wait between file checks
	authority.mu.Unlock()
	after, err := authority.Certificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !verifies(after.Leaf, second, "api.example.com") || verifies(after.Leaf, first, "api.example.com") {
		t.Fatal("leaf was not reissued under the rotated CA")
	}
}

// A swap of the mounted files can be read half way: a new certificate with the
// old key. The loaded CA stays in use and the failure is logged once, however
// often the files are rechecked. The matching pair then loads and is reported.
func TestFailedReloadKeepsAuthorityAndIsLogged(t *testing.T) {
	dir := t.TempDir()
	certificateFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	first := writeAuthority(t, dir, true)
	var logged bytes.Buffer
	authority, err := Load(certificateFile, keyFile, log.New(&logged, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	second := writeAuthority(t, dir, true)
	newKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	modified := time.Now()
	// publish writes the key and moves both modification times, then asks for
	// a leaf with the wait between file checks skipped.
	publish := func(key []byte) *x509.Certificate {
		t.Helper()
		if err := os.WriteFile(keyFile, key, 0600); err != nil {
			t.Fatal(err)
		}
		modified = modified.Add(time.Hour)
		for _, name := range []string{certificateFile, keyFile} {
			if err := os.Chtimes(name, modified, modified); err != nil {
				t.Fatal(err)
			}
		}
		authority.mu.Lock()
		authority.checkedAt = time.Time{}
		authority.mu.Unlock()
		certificate, err := authority.Certificate("api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		return certificate.Leaf
	}
	for range 2 {
		if leaf := publish(oldKey); !verifies(leaf, first, "api.example.com") {
			t.Fatal("a mismatched pair replaced the loaded CA")
		}
	}
	failure := `{"event":"interception_ca_reload_failed","reason":"interception CA certificate and key do not match"`
	if got := logged.String(); strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, failure) || !strings.Contains(got, certificateFile) || !strings.Contains(got, keyFile) {
		t.Fatalf("want one line naming the cause and both paths, got %q", got)
	}
	logged.Reset()
	if leaf := publish(newKey); !verifies(leaf, second, "api.example.com") {
		t.Fatal("the matching pair was not loaded")
	}
	if got := logged.String(); strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, `{"event":"interception_ca_reloaded"`) {
		t.Fatalf("want one line for the successful reload, got %q", got)
	}
}
