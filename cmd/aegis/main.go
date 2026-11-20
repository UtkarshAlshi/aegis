package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"log/slog"
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
	"aegis/internal/proxy"
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
	mux := g.BrowserRoutes(rp, false)
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return errors.New("invalid TLS key pair")
	}
	server := proxy.Server(cfg.Listen, mux)
	server.TLSConfig.Certificates = []tls.Certificate{cert}
	server.TLSConfig.Time = c.Now
	server.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}), slog.LevelDebug)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-signals:
				if policy.Reload(cfg.Policy) != nil {
					slog.Warn("policy reload rejected")
				} else {
					slog.Info("policy reloaded")
				}
			}
		}
	}()
	return server.ListenAndServeTLS("", "")
}

func main() {
	path := flag.String("config", "aegis.yaml", "gateway configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}
