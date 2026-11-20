package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"aegis/internal/audit"
	"aegis/internal/authz"
	"aegis/internal/clock"
	"aegis/internal/jwtx"
	"aegis/internal/oidc"
	"aegis/internal/pki"
	"aegis/internal/proxy"
	"aegis/internal/samlx"
	"aegis/internal/session"
	"aegis/internal/testidp"
	jose "github.com/go-jose/go-jose/v4"
)

const policyYAML = `rules:
- path_prefix: /protected
  methods: [GET, HEAD]
  groups: [engineering]
  machines: ["spiffe://aegis/service/robot"]
`

func listener(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

type endpoints struct {
	browser, machine, oidc, saml, dir string
}

func run(ctx context.Context, browserPort, machinePort int, announce func(endpoints)) error {
	browserListener, err := listener(browserPort)
	if err != nil {
		return err
	}
	defer browserListener.Close()
	machineListener, err := listener(machinePort)
	if err != nil {
		return err
	}
	defer machineListener.Close()
	origin := fmt.Sprintf("https://localhost:%d", browserListener.Addr().(*net.TCPAddr).Port)
	machineURL := fmt.Sprintf("https://localhost:%d/protected", machineListener.Addr().(*net.TCPAddr).Port)

	c := clock.Real{}
	caPair, err := pki.NewCA(c, 48*time.Hour)
	if err != nil {
		return err
	}
	ca, err := pki.ParseCA(c, caPair)
	if err != nil {
		return err
	}
	serverPair, err := ca.IssueServer([]string{"localhost", "127.0.0.1"}, 24*time.Hour)
	if err != nil {
		return err
	}
	cert, err := serverPair.TLS()
	if err != nil {
		return err
	}
	clientPair, err := ca.IssueClient("robot", 24*time.Hour)
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "aegis-demo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for name, data := range map[string][]byte{"ca.crt": caPair.Certificate, "robot.crt": clientPair.Certificate, "robot.key": clientPair.Key, "revoked.txt": nil} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return err
		}
	}
	certConfig := func() *tls.Config {
		cfg := proxy.TLSConfig()
		cfg.Time = c.Now
		cfg.Certificates = []tls.Certificate{cert}
		return cfg
	}
	oidp, err := testidp.NewOIDCTLS(c, "aegis-demo", origin+"/auth/oidc/callback", certConfig())
	if err != nil {
		return err
	}
	defer oidp.Server.Close()
	sidp, err := testidp.NewSAML(c, serverPair, certConfig())
	if err != nil {
		return err
	}
	defer sidp.Server.Close()

	a := &audit.Log{Logger: slog.New(slog.NewJSONHandler(os.Stderr, nil))}
	sessions := session.New(c, 30*time.Minute, 8*time.Hour)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPair.Certificate) {
		return errors.New("demo CA unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, Time: c.Now}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	rp, err := oidc.New(ctx, c, client, oidp.Config(), sessions, a)
	if err != nil {
		return err
	}
	if err = rp.Ready(ctx); err != nil {
		return err
	}
	m, err := sidp.Metadata()
	if err != nil {
		return err
	}
	sp, err := samlx.New(c, origin, sidp.EntityID(), m, sessions, a)
	if err != nil {
		return err
	}
	m, err = sp.MetadataXML()
	if err != nil || !sidp.RegisterSP(m) {
		return errors.New("could not register demo SP")
	}

	const audience = "aegis-demo-upstream"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	signer, err := jwtx.NewSigner(key)
	if err != nil {
		return err
	}
	cache := jwtx.NewCache(c, client, origin+"/.well-known/jwks.json", 0, jose.ES256)
	zero := time.Duration(0)
	verify, err := jwtx.NewVerifier(c, origin, audience, &zero, cache.Lookup, jose.ES256)
	if err != nil {
		return err
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertion, err := verify.Verify(r.Context(), r.Header.Get(proxy.AssertionHeader), "")
		if err != nil {
			http.Error(w, "valid gateway assertion required", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": assertion.Subject, "kind": assertion.Kind, "provider": assertion.Provider, "groups": assertion.Groups, "path": r.URL.Path})
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		return err
	}
	policy := &authz.Engine{}
	if err = policy.Load([]byte(policyYAML)); err != nil {
		return err
	}
	shared, err := proxy.New(proxy.Gateway{Clock: c, Sessions: sessions, Policy: policy, Signer: signer, Issuer: origin, Audience: audience, Audit: a}, u)
	if err != nil {
		return err
	}
	routes := shared.BrowserRoutes(rp, true)
	sp.Register(routes)
	ready := func(ctx context.Context) error {
		if err := sp.Ready(); err != nil {
			return err
		}
		return rp.Ready(ctx)
	}
	browser := proxy.Server(browserListener.Addr().String(), shared.BrowserHandler(routes, ready))
	browser.TLSConfig = certConfig()
	browser.ErrorLog = log.New(io.Discard, "", 0)
	machineGateway := *shared
	clients, err := pki.NewClients(c, caPair.Certificate, filepath.Join(dir, "revoked.txt"))
	if err != nil {
		return err
	}
	machineGateway.Machine = clients.Authenticate
	machine := proxy.Server(machineListener.Addr().String(), &machineGateway)
	machine.TLSConfig = certConfig()
	machine.ErrorLog = log.New(audit.TLSLog{Audit: a}, "", 0)
	clients.Configure(machine.TLSConfig)
	stopped := make(chan error, 2)
	go func() { stopped <- browser.ServeTLS(browserListener, "", "") }()
	go func() { stopped <- machine.ServeTLS(machineListener, "", "") }()

	announce(endpoints{origin, machineURL, oidp.Server.URL, sidp.EntityID(), dir})

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-stopped:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(serveErr, browser.Shutdown(shutdown), machine.Shutdown(shutdown))
}

func printEndpoints(e endpoints) {
	fmt.Printf("Browser (OIDC alice, SAML bob)  %s/\n", e.browser)
	fmt.Printf("Mock OIDC                      %s\n", e.oidc)
	fmt.Printf("Mock SAML metadata             %s\n", e.saml)
	fmt.Printf("Demo CA for browser trust      %s\n", filepath.Join(e.dir, "ca.crt"))
	fmt.Printf("Machine (robot)                %s\n", e.machine)
	fmt.Printf("curl --cacert %q --cert %q --key %q %q\n", filepath.Join(e.dir, "ca.crt"), filepath.Join(e.dir, "robot.crt"), filepath.Join(e.dir, "robot.key"), e.machine)

}

func main() {
	browser := flag.Int("browser-port", 8443, "browser HTTPS port (0 chooses a port)")
	machine := flag.Int("machine-port", 8444, "mTLS port (0 chooses a port)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *browser, *machine, printEndpoints); err != nil {
		slog.Error("demo stopped", "error", err)
		os.Exit(1)
	}
}
