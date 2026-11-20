package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aegis/internal/clock"
)

func readyCA(t *testing.T, c clock.Clock) (*CA, Pair) {
	t.Helper()
	pair, err := NewCA(c, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCA(c, pair)
	if err != nil {
		t.Fatal(err)
	}
	return ca, pair
}

func tlsPair(t *testing.T, p Pair, err error) tls.Certificate {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestMTLSHandshakeAndRevocation(t *testing.T) {
	c := clock.NewManual(time.Unix(1800000000, 0))
	ca, root := readyCA(t, c)
	another, _ := readyCA(t, c)
	sp, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	server := tlsPair(t, sp, err)
	robotPair, err := ca.IssueClient("robot", time.Hour)
	robot := tlsPair(t, robotPair, err)
	leaf, err := ParseCertificate(robotPair.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := ca.IssueClient("robot", time.Second)
	expiredCert := tlsPair(t, expired, err)
	incorrectCA, err := another.IssueClient("robot", time.Hour)
	badCA := tlsPair(t, incorrectCA, err)
	u, _ := url.Parse("spiffe://other/service/robot")
	mismatched, err := ca.issue(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}}, time.Hour)
	badSAN := tlsPair(t, mismatched, err)
	noEKU, err := ca.issue(&x509.Certificate{URIs: []*url.URL{{Scheme: "spiffe", Host: "aegis", Path: "/service/robot"}}}, time.Hour)
	unspecifiedEKU := tlsPair(t, noEKU, err)
	rev := filepath.Join(t.TempDir(), "revoked.txt")
	if err = os.WriteFile(rev, nil, 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := NewClients(c, root.Certificate, rev)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := clients.Authenticate(r)
		if err != nil {
			http.Error(w, "denied", 401)
			return
		}
		_, _ = io.WriteString(w, id.Subject)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{server}}
	clients.Configure(srv.TLS)
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(root.Certificate)
	c.Advance(2 * time.Second)
	getClient := func(cert tls.Certificate, hostname string) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Time: c.Now, ServerName: hostname,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	for _, tc := range []struct {
		name     string
		cert     tls.Certificate
		hostname string
	}{
		{"expired certificate", expiredCert, ""}, {"wrong EKU", server, ""}, {"missing explicit client EKU", unspecifiedEKU, ""},
		{"wrong CA", badCA, ""}, {"wrong SPIFFE SAN", badSAN, ""}, {"server SAN mismatch", robot, "localhost"},
		{"no certificate", tls.Certificate{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if res, err := getClient(tc.cert, tc.hostname).Get(srv.URL); err == nil {
				res.Body.Close()
				t.Fatal("invalid handshake accepted")
			}
		})
	}
	presentedRoot, err := ParseCertificate(root.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	withRoot := robot
	withRoot.Certificate = append(append([][]byte(nil), robot.Certificate...), presentedRoot.Raw)
	res, err := getClient(withRoot, "").Get(srv.URL)
	if err != nil {
		t.Fatalf("TLS client sending the configured root: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("client chain with the configured root was denied")
	}

	live := getClient(robot, "")
	res, err = live.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || string(body) != ServicePrefix+"robot" {
		t.Fatal("valid identity did not map")
	}
	if err = Revoke(rev, SerialHex(leaf)); err != nil {
		t.Fatal(err)
	}
	res, err = live.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("revoked cert still usable on live connection")
	}
	if res, err = getClient(robot, "").Get(srv.URL); err == nil {
		res.Body.Close()
		t.Fatal("revoked cert passed handshake")
	}
	if err = os.WriteFile(rev, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if res, err = getClient(robot, "").Get(srv.URL); err == nil {
		res.Body.Close()
		t.Fatal("malformed revocations failed open")
	}
}

func TestTLSCertificateRotation(t *testing.T) {
	c := clock.NewManual(time.Unix(1800000000, 0))
	ca, root := readyCA(t, c)
	first, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	write := func(path string, content []byte) {
		t.Helper()
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(crt, first.Certificate)
	write(key, first.Key)
	reload, err := NewReloader(c, crt, key, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: reload.GetCertificate, Time: c.Now}
	// httptest supplies a default certificate unless provided one, so use net/http directly.
	listener := server.Listener
	httpServer := &http.Server{Handler: server.Config.Handler, TLSConfig: server.TLS}
	defer httpServer.Close()
	go func() { _ = httpServer.ServeTLS(listener, "", "") }()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(root.Certificate)
	dial := func() *tls.Conn {
		t.Helper()
		d := &net.Dialer{Timeout: 3 * time.Second}
		nc, err := tls.DialWithDialer(d, "tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, Time: c.Now, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		return nc
	}
	old := dial()
	defer old.Close()
	oldSerial := SerialHex(old.ConnectionState().PeerCertificates[0])
	write(crt, second.Certificate)
	if reload.Reload() == nil {
		t.Fatal("mismatched key accepted")
	}
	same := dial()
	if SerialHex(same.ConnectionState().PeerCertificates[0]) != oldSerial {
		t.Fatal("bad rotation changed active certificate")
	}
	same.Close()
	write(key, second.Key)
	if err := reload.Reload(); err != nil {
		t.Fatal(err)
	}
	fresh := dial()
	defer fresh.Close()
	if SerialHex(fresh.ConnectionState().PeerCertificates[0]) == oldSerial {
		t.Fatal("new handshakes retained old certificate")
	}
	if _, err = io.WriteString(old, "GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = old.SetReadDeadline((clock.Real{}).Now().Add(3 * time.Second))
	if data, err := io.ReadAll(old); err != nil || len(data) == 0 {
		t.Fatalf("existing TLS connection dropped: %v", err)
	}
}

func TestIssuedKeyAndCertificateProfiles(t *testing.T) {
	c := clock.NewManual(time.Unix(1800000000, 0))
	ca, _ := readyCA(t, c)
	if _, err := ca.IssueClient("../bad", time.Hour); err == nil {
		t.Fatal("invalid service name accepted")
	}
	if _, err := ca.IssueServer([]string{"*.example"}, time.Hour); err == nil {
		t.Fatal("wildcard SAN accepted")
	}
	if _, err := ca.IssueServer([]string{"localhost"}, 48*time.Hour); err == nil {
		t.Fatal("issued certificate outliving CA")
	}
	p, err := ca.IssueClient("robot", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(p.Key)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.(*ecdsa.PrivateKey).Sign(rand.Reader, make([]byte, 32), nil); err != nil {
		t.Fatal(err)
	}
}
