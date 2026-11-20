package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"strings"

	"aegis/internal/clock"
	"aegis/internal/session"
)

type Clients struct {
	ca          *x509.Certificate
	roots       *x509.CertPool
	revocations string
	clock       clock.Clock
}

func NewClients(c clock.Clock, pem []byte, revocations string) (*Clients, error) {
	ca, err := ParseCertificate(pem)
	if err != nil || c == nil {
		return nil, errors.New("invalid mTLS CA")
	}
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || c.Now().Before(ca.NotBefore) || !c.Now().Before(ca.NotAfter) {
		return nil, errors.New("mTLS requires a currently valid internal root CA")
	}
	if _, err = readRevocations(revocations); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &Clients{ca, pool, revocations, c}, nil
}

func (m *Clients) Configure(cfg *tls.Config) {
	cfg.Time = m.clock.Now
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = m.roots
	cfg.SessionTicketsDisabled = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		_, err := m.identity(cs)
		return err
	}
}

func (m *Clients) Authenticate(r *http.Request) (session.Identity, error) {
	if r.TLS == nil {
		return session.Identity{}, errors.New("client TLS required")
	}
	return m.identity(*r.TLS)
}

func (m *Clients) identity(cs tls.ConnectionState) (session.Identity, error) {
	var id session.Identity
	// TLS clients may send the trust anchor along with a directly issued leaf.
	chain := cs.PeerCertificates
	if len(chain) == 0 || len(chain) > 2 || (len(chain) == 2 && !chain[1].Equal(m.ca)) || len(cs.VerifiedChains) == 0 {
		return id, errors.New("direct verified client certificate required")
	}
	leaf := chain[0]
	now := m.clock.Now()
	if leaf.CheckSignatureFrom(m.ca) != nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || now.Before(m.ca.NotBefore) || !now.Before(m.ca.NotAfter) {
		return id, errors.New("client certificate rejected")
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return id, errors.New("one URI SAN required")
	}
	uri := leaf.URIs[0].String()
	service, ok := strings.CutPrefix(uri, ServicePrefix)
	if !ok || !serviceName.MatchString(service) {
		return id, errors.New("invalid service URI")
	}
	revoked, err := readRevocations(m.revocations)
	if err != nil || revoked[SerialHex(leaf)] {
		return id, errors.New("client revocation check failed")
	}
	return session.Identity{Subject: uri, Kind: "machine", Provider: "mtls"}, nil
}
