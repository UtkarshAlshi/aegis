package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
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
	raw, err := pki.ReadFile(path, 256<<10)
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

func run(ctx context.Context, path string) error {
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
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
	var ready func(context.Context) error
	if rp != nil {
		ready = rp.Ready
	}
	if saml != nil {
		oidcReady := ready
		ready = func(ctx context.Context) error {
			if err := saml.Ready(); err != nil {
				return err
			}
			if oidcReady != nil {
				return oidcReady(ctx)
			}
			return nil
		}
	}
	browser := makeServer(cfg.Listen, g.BrowserHandler(mux, ready))
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
		srv.ErrorLog = log.New(audit.TLSLog{Audit: a}, "", 0)
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
	listeners := make([]net.Listener, 0, len(servers))
	for _, srv := range servers {
		l, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return err
		}
		defer l.Close()
		listeners = append(listeners, l)
	}
	failed := make(chan error, len(servers))
	for i, srv := range servers {
		defer srv.Close()
		go func() { failed <- srv.ServeTLS(listeners[i], "", "") }()
	}
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-failed:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		serveErr = errors.Join(serveErr, srv.Shutdown(shutdown))
	}
	return serveErr

}

func main() {
	path := flag.String("config", "aegis.yaml", "gateway configuration file")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *path); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}
