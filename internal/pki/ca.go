package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"aegis/internal/clock"
)

var serviceName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
var dnsName = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

const ServicePrefix = "spiffe://aegis/service/"
const maxPEM = 256 << 10

type Pair struct{ Certificate, Key []byte }

func (p Pair) TLS() (tls.Certificate, error) { return tls.X509KeyPair(p.Certificate, p.Key) }

func privateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}

func NewCA(c clock.Clock, lifetime time.Duration) (Pair, error) {
	if c == nil || lifetime <= time.Minute || lifetime > 10*365*24*time.Hour {
		return Pair{}, errors.New("invalid CA lifetime")
	}
	key, keyPEM, err := privateKey()
	if err != nil {
		return Pair{}, err
	}
	number, err := serial()
	if err != nil {
		return Pair{}, err
	}
	now := c.Now()
	tmpl := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: "Aegis internal CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Pair{}, fmt.Errorf("create CA: %w", err)
	}
	return Pair{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM}, nil
}

type CA struct {
	c    clock.Clock
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func ParseCA(c clock.Clock, p Pair) (*CA, error) {
	pair, err := p.TLS()
	if err != nil || c == nil {
		return nil, errors.New("invalid CA key pair")
	}
	cert, err := ParseCertificate(p.Certificate)
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("invalid internal CA")
	}
	return &CA{c, cert, key}, nil
}

func ParseCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (a *CA) IssueServer(sans []string, lifetime time.Duration) (Pair, error) {
	tmpl := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if len(sans) == 0 {
		return Pair{}, errors.New("server SAN required")
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		if len(san) > 253 || !dnsName.MatchString(san) {
			return Pair{}, errors.New("invalid DNS SAN")
		}
		tmpl.DNSNames = append(tmpl.DNSNames, san)
	}
	return a.issue(tmpl, lifetime)
}

func (a *CA) IssueClient(name string, lifetime time.Duration) (Pair, error) {
	if !serviceName.MatchString(name) {
		return Pair{}, errors.New("invalid service name")
	}
	u := &url.URL{Scheme: "spiffe", Host: "aegis", Path: "/service/" + name}
	tmpl := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}
	return a.issue(tmpl, lifetime)
}

func (a *CA) issue(tmpl *x509.Certificate, lifetime time.Duration) (Pair, error) {
	now := a.c.Now()
	if lifetime <= 0 || lifetime > 365*24*time.Hour || now.Before(a.cert.NotBefore) || now.Add(lifetime).After(a.cert.NotAfter) {
		return Pair{}, errors.New("certificate lifetime exceeds allowed bounds or CA validity")
	}
	key, keyPEM, err := privateKey()
	if err != nil {
		return Pair{}, err
	}
	tmpl.SerialNumber, err = serial()
	if err != nil {
		return Pair{}, err
	}
	tmpl.NotBefore = maxTime(now.Add(-time.Minute), a.cert.NotBefore)
	tmpl.NotAfter = now.Add(lifetime)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return Pair{}, fmt.Errorf("issue certificate: %w", err)
	}
	return Pair{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM}, nil
}

func maxTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}

func ReadFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file too large")
	}
	return raw, nil
}

func LoadPair(cert, key string) (Pair, error) {
	c, err := ReadFile(cert, maxPEM)
	if err != nil {
		return Pair{}, err
	}
	k, err := ReadFile(key, maxPEM)
	if err != nil {
		return Pair{}, err
	}
	return Pair{c, k}, nil
}

func SerialHex(c *x509.Certificate) string { return strings.ToLower(c.SerialNumber.Text(16)) }
