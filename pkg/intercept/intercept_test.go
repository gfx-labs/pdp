package intercept

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
	if _, err := Load(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err == nil {
		t.Fatal("a certificate without CA usage was loaded as the interception CA")
	}
}

// cert-manager renews the CA by rewriting the mounted files. New leaves must
// come from the new CA, and a cached leaf from the old one must not be served.
func TestRotatedAuthorityReplacesCachedLeaves(t *testing.T) {
	dir := t.TempDir()
	first := writeAuthority(t, dir, true)
	authority, err := Load(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
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
