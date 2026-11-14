// Package intercept mints short-lived leaf certificates from an administrator
// CA so the gateway can terminate TLS for a destination and read the request.
package intercept

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

const (
	leafLifetime = 24 * time.Hour
	// A leaf is replaced while clients can still verify the one in flight.
	leafRenewBefore = time.Hour
	cacheEntries    = 1024
	recheckInterval = time.Minute
	maxFileBytes    = 1 << 20
)

type leaf struct {
	host        string
	certificate *tls.Certificate
	renewAt     time.Time
}

// Authority holds the signing key. Anyone holding that key can impersonate every
// host its certificate permits to every workload that trusts its root.
type Authority struct {
	certificateFile, keyFile string
	logger                   *log.Logger

	mu          sync.Mutex
	chain       [][]byte
	certificate *x509.Certificate
	key         crypto.Signer
	loadedAt    time.Time
	modified    [2]time.Time
	checkedAt   time.Time
	// failure is the cause of the last failed reload, so that a failure that
	// repeats at every recheck is logged once.
	failure string
	order   *list.List
	leaves  map[string]*list.Element
}

// Load reads a PEM CA certificate, followed by any intermediates below the root
// that workloads trust, and its PEM private key. Later reloads are reported to
// logger, which may be nil.
func Load(certificateFile, keyFile string, logger *log.Logger) (*Authority, error) {
	a := &Authority{certificateFile: certificateFile, keyFile: keyFile, logger: logger}
	if err := a.reload(); err != nil {
		return nil, err
	}
	return a, nil
}

func readFile(path string) ([]byte, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return nil, time.Time{}, errors.New("interception CA file is unreadable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, errors.New("interception CA file is unreadable")
	}
	return data, info.ModTime(), nil
}

func (a *Authority) reload() error {
	certificatePEM, certificateTime, err := readFile(a.certificateFile)
	if err != nil {
		return err
	}
	keyPEM, keyTime, err := readFile(a.keyFile)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return errors.New("interception CA certificate and key do not match")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("invalid interception CA certificate")
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	now := time.Now()
	if !ok || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("interception certificate is not a currently valid CA")
	}
	a.chain, a.certificate, a.key = pair.Certificate, certificate, key
	a.loadedAt, a.checkedAt, a.modified = now, now, [2]time.Time{certificateTime, keyTime}
	a.order, a.leaves = list.New(), make(map[string]*list.Element)
	return nil
}

// refresh picks up a rotated CA, such as a cert-manager renewal, without a
// restart. A failed reload keeps the CA that is already loaded.
func (a *Authority) refresh(now time.Time) {
	if now.Sub(a.checkedAt) < recheckInterval {
		return
	}
	a.checkedAt = now
	certificateInfo, certificateErr := os.Stat(a.certificateFile)
	keyInfo, keyErr := os.Stat(a.keyFile)
	if certificateErr != nil || keyErr != nil {
		a.report(errors.New("interception CA file is unreadable"))
		return
	}
	if certificateInfo.ModTime().Equal(a.modified[0]) && keyInfo.ModTime().Equal(a.modified[1]) {
		return
	}
	a.report(a.reload())
}

// report logs the outcome of a reload attempt: a failure when its cause
// changes, and every success. The causes are fixed texts from this package,
// so no file content can reach the log.
func (a *Authority) report(err error) {
	event := struct {
		Event           string `json:"event"`
		Reason          string `json:"reason,omitempty"`
		CertificateFile string `json:"certificate_file"`
		KeyFile         string `json:"key_file"`
	}{"interception_ca_reloaded", "", a.certificateFile, a.keyFile}
	if err != nil {
		if err.Error() == a.failure {
			return
		}
		event.Event, event.Reason = "interception_ca_reload_failed", err.Error()
	}
	a.failure = event.Reason
	if a.logger == nil {
		return
	}
	if line, marshalErr := json.Marshal(event); marshalErr == nil {
		a.logger.Print(string(line))
	}
}

// Certificate returns a leaf for one already validated host name or IP literal.
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	if host == "" || len(host) > 253 {
		return nil, errors.New("invalid interception host")
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refresh(now)
	if element, ok := a.leaves[host]; ok {
		cached := element.Value.(*leaf)
		if now.Before(cached.renewAt) {
			a.order.MoveToFront(element)
			return cached.certificate, nil
		}
		a.order.Remove(element)
		delete(a.leaves, host)
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(a.certificate.NotAfter) {
		notAfter = a.certificate.NotAfter
	}
	if !now.Before(notAfter) {
		return nil, errors.New("interception CA has expired")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New("cannot generate interception key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, errors.New("cannot generate interception serial")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.key)
	if err != nil {
		return nil, errors.New("cannot sign interception certificate")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("cannot sign interception certificate")
	}
	// The chain lets a client that trusts only the root verify the leaf.
	certificate := &tls.Certificate{Certificate: append([][]byte{der}, a.chain...), PrivateKey: key, Leaf: parsed}
	a.leaves[host] = a.order.PushFront(&leaf{host: host, certificate: certificate, renewAt: notAfter.Add(-leafRenewBefore)})
	for a.order.Len() > cacheEntries {
		oldest := a.order.Back()
		a.order.Remove(oldest)
		delete(a.leaves, oldest.Value.(*leaf).host)
	}
	return certificate, nil
}
