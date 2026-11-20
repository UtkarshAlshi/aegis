package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"

	"aegis/internal/clock"
)

type Reloader struct {
	certPath, keyPath, hostname string
	clock                       clock.Clock
	current                     atomic.Pointer[tls.Certificate]
	mu                          sync.Mutex
	loaded                      Pair
}

func NewReloader(c clock.Clock, cert, key, host string) (*Reloader, error) {
	r := &Reloader{clock: c, certPath: cert, keyPath: key, hostname: host}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := r.current.Load()
	if cert == nil || r.clock.Now().Before(cert.Leaf.NotBefore) || !r.clock.Now().Before(cert.Leaf.NotAfter) {
		return nil, errors.New("server certificate unavailable")
	}
	return cert, nil
}

func (r *Reloader) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := LoadPair(r.certPath, r.keyPath)
	if err != nil {
		return err
	}
	if bytes.Equal(p.Certificate, r.loaded.Certificate) && bytes.Equal(p.Key, r.loaded.Key) {
		return nil
	}
	pair, err := p.TLS()
	if err != nil {
		return errors.New("invalid TLS key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || (r.hostname != "" && leaf.VerifyHostname(r.hostname) != nil) ||
		r.clock.Now().Before(leaf.NotBefore) || !r.clock.Now().Before(leaf.NotAfter) {
		return errors.New("invalid server certificate")
	}
	pair.Leaf = leaf
	r.loaded = p
	r.current.Store(&pair)
	return nil
}
