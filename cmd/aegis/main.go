package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aegis/internal/audit"
	"aegis/internal/authz"
	"aegis/internal/clock"
	"aegis/internal/config"
	"aegis/internal/jwtx"
	"aegis/internal/oidc"
	"aegis/internal/pki"
	"aegis/internal/proxy"
	"aegis/internal/samlx"
	"aegis/internal/session"
)

func signerFromFile(path string) (*jwtx.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("expected one PKCS#8 PEM key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid assertion key")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("expected ECDSA assertion key")
	}
	return jwtx.NewSigner(ec)
}

func run(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	c := clock.Real{}
	a := &audit.Log{Logger: slog.Default()}
	s := session.New(c, 30*time.Minute, 8*time.Hour)
	policy := &authz.Engine{}
	if policy.Reload(cfg.Policy) != nil {
		return errors.New("invalid initial policy")
	}
	signer, err := signerFromFile(cfg.AssertionKey)
	if err != nil {
		return err
	}
	upstream, err := config.UpstreamURL(cfg.Upstream)
	if err != nil {
		return err
	}
	g, err := proxy.New(proxy.Gateway{Clock: c, Sessions: s, Policy: policy, Signer: signer, Issuer: cfg.PublicURL, Audience: cfg.Audience, Trusted: cfg.TrustedProxies, Audit: a}, upstream)
	if err != nil {
		return err
	}
	var rp *oidc.RP
	if cfg.OIDC != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		rp, err = oidc.New(ctx, c, nil, *cfg.OIDC, s, a)
		if err != nil {
			return err
		}
		if rp.Ready(ctx) != nil {
			return errors.New("initial OIDC JWKS unavailable")
		}
	}
	var saml *samlx.SP
	if cfg.SAML != nil {
		raw, err := pki.ReadFile(cfg.SAML.Metadata, 256<<10)
		if err != nil {
			return errors.New("SAML metadata unavailable")
		}
		saml, err = samlx.New(c, cfg.PublicURL, cfg.SAML.EntityID, raw, s, a)
		if err != nil {
			return err
		}
	}
	mux := g.BrowserRoutes(rp, saml != nil)
	if saml != nil {
		saml.Register(mux)
	}
	origin, _ := oidc.SecureURL(cfg.PublicURL)
	cert, err := pki.NewReloader(c, cfg.TLSCert, cfg.TLSKey, origin.Hostname())
	if err != nil {
		return err
	}
	makeServer := func(addr string, h http.Handler) *http.Server {
		srv := proxy.Server(addr, h)
		srv.TLSConfig.GetCertificate = cert.GetCertificate
		srv.TLSConfig.Time = c.Now
		srv.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelDebug)
		return srv
	}
	browser := makeServer(cfg.Listen, mux)
	servers := []*http.Server{browser}
	if cfg.MTLS != nil {
		raw, err := pki.ReadFile(cfg.MTLS.CA, 256<<10)
		if err != nil {
			return errors.New("mTLS CA unavailable")
		}
		clients, err := pki.NewClients(c, raw, cfg.MTLS.Revocations)
		if err != nil {
			return err
		}
		machine := *g
		machine.Machine = clients.Authenticate
		srv := makeServer(cfg.MTLS.Listen, &machine)
		clients.Configure(srv.TLSConfig)
		servers = append(servers, srv)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_ = cert.Reload()
			case <-signals:
				if cert.Reload() != nil {
					slog.Warn("certificate reload rejected")
				}
				if policy.Reload(cfg.Policy) != nil {
					slog.Warn("policy reload rejected")
				} else {
					slog.Info("policy reloaded")
				}
			}
		}
	}()
	failed := make(chan error, len(servers))
	for _, srv := range servers {
		defer srv.Close()
		go func() { failed <- srv.ListenAndServeTLS("", "") }()
	}
	return <-failed

}

func main() {
	path := flag.String("config", "aegis.yaml", "gateway configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}
