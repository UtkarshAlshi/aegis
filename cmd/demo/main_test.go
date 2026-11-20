package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"aegis/internal/pki"
	"aegis/internal/proxy"
)

var values = regexp.MustCompile(`name="(SAMLResponse|RelayState|csrf)" value="([^"]*)"`)

func TestDemoThroughHTTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reports := make(chan endpoints, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, 0, 0, func(info endpoints) { reports <- info }) }()
	var info endpoints
	select {
	case info = <-reports:
	case err := <-done:
		cancel()
		t.Fatalf("start demo: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("demo startup timed out")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("demo shutdown timed out")
		}
	})
	root, err := os.ReadFile(filepath.Join(info.dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		t.Fatal("could not trust demo CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second}

	get := func(client *http.Client, target string, want int) (string, *url.URL) {
		t.Helper()
		r, err := http.NewRequest("GET", target, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(proxy.AssertionHeader, "untrusted")
		status, body, u := send(t, client, r)
		if status != want {
			t.Fatalf("GET %s: got %d, want %d", u.Path, status, want)
		}
		return body, u
	}
	post := func(target string, form url.Values, want int) string {
		t.Helper()
		req, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		status, body, u := send(t, browser, req)
		if status != want {
			t.Fatalf("POST ended at %s: got %d, want %d", u.Path, status, want)
		}
		return body
	}
	fields := func(body string) url.Values {
		form := url.Values{}
		for _, match := range values.FindAllStringSubmatch(body, -1) {
			form.Set(match[1], html.UnescapeString(match[2]))
		}
		return form
	}
	check := func(raw, subject, kind, idp string) {
		t.Helper()
		var claims map[string]any
		if json.Unmarshal([]byte(raw), &claims) != nil || claims["subject"] != subject || claims["kind"] != kind || claims["provider"] != idp {
			t.Fatal("unexpected asserted identity")
		}
	}

	get(browser, info.browser+"/healthz", 204)
	get(browser, info.browser+"/readyz", 204)
	get(browser, info.browser+"/protected", 401)
	_, authorization := get(browser, info.browser+"/auth/oidc/login", 200)
	home := post(authorization.String(), nil, 200)
	body, _ := get(browser, info.browser+"/protected", 200)
	check(body, "alice", "user", "oidc")
	post(info.browser+"/auth/logout", fields(home), 200)
	get(browser, info.browser+"/protected", 401)

	_, samlLogin := get(browser, info.browser+"/auth/saml/login", 200)
	q := samlLogin.Query()
	q.Set("demo", "1")
	samlLogin.RawQuery = q.Encode()
	form, _ := get(browser, samlLogin.String(), 200)
	home = post(info.browser+"/auth/saml/acs", fields(form), 200)
	body, _ = get(browser, info.browser+"/protected", 200)
	check(body, "bob", "user", "saml")
	post(info.browser+"/auth/logout", fields(home), 200)
	get(browser, info.browser+"/protected", 401)

	if res, err := browser.Get(info.machine); err == nil {
		res.Body.Close()
		t.Fatal("machine listener accepted no certificate")
	}
	robot, err := pki.LoadPair(filepath.Join(info.dir, "robot.crt"), filepath.Join(info.dir, "robot.key"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := robot.TLS()
	if err != nil {
		t.Fatal(err)
	}
	machineTransport := transport.Clone()
	machineTransport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	defer machineTransport.CloseIdleConnections()
	machine := &http.Client{Transport: machineTransport, Timeout: 5 * time.Second}
	body, _ = get(machine, info.machine, 200)
	check(body, "spiffe://aegis/service/robot", "machine", "mtls")
	metrics, _ := get(browser, info.browser+"/metrics", 200)
	if !strings.Contains(metrics, `aegis_auth_events_total{outcome="success"}`) {
		t.Fatal("missing audit metric")
	}
}

func send(t *testing.T, c *http.Client, r *http.Request) (int, string, *url.URL) {
	t.Helper()
	res, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(raw), res.Request.URL
}
