package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegis/internal/authz"
	"aegis/internal/clock"
	"aegis/internal/jwtx"
	"aegis/internal/session"
	jose "github.com/go-jose/go-jose/v4"
)

func TestProxyIdentityAndAssertion(t *testing.T) {
	c := clock.NewManual(time.Unix(100000, 0))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwtx.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	skew := time.Duration(0)
	verifier, err := jwtx.NewVerifier(c, "gateway", "app", &skew, signer.Lookup, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, key := range []string{"X-Auth-User", "X-Forwarded-User", "X-Remote-User", "X-Unknown-Identity", "Authorization", "Cookie", "X-CSRF-Token"} {
			if r.Header.Get(key) != "" {
				t.Errorf("spoofed header reached upstream: %s", key)
			}
		}
		raw := r.Header.Get(AssertionHeader)
		claim, err := verifier.Verify(r.Context(), raw, "")
		if err != nil || claim.Subject != "alice" || claim.Kind != "user" || claim.Expiry.Time().Sub(claim.IssuedAt.Time()) != time.Minute {
			t.Errorf("upstream received invalid assertion: %v", err)
		}
		w.Header().Set("Set-Cookie", "bad=1")
		w.Header().Set("X-Auth-Assertion", "secret")
		seen <- raw
		_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-For"))
	}))
	defer upstream.Close()
	policy := &authz.Engine{}
	if err = policy.Load([]byte("rules: [{path_prefix: /protected, methods: [GET, POST], groups: [dev]}]")); err != nil {
		t.Fatal(err)
	}
	s := session.New(c, 2*time.Minute, time.Hour)
	u, _ := url.Parse(upstream.URL)
	g, err := New(Gateway{Clock: c, Sessions: s, Policy: policy, Signer: signer, Issuer: "gateway", Audience: "app", Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, u)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	if err = s.Login(login, httptest.NewRequest("GET", "/", nil), session.Identity{Subject: "alice", Kind: "user", Groups: []string{"dev"}}); err != nil {
		t.Fatal(err)
	}
	request := func(method, peer string, auth bool) *httptest.ResponseRecorder {
		w, r := httptest.NewRecorder(), httptest.NewRequest(method, "/protected", nil)
		r.RemoteAddr = peer
		for _, name := range []string{AssertionHeader, "X-Auth-User", "X-Forwarded-User", "X-Remote-User", "X-Unknown-Identity", "Authorization"} {
			r.Header.Set(name, "spoofed")
		}
		r.Header.Set("X-Forwarded-For", "203.0.113.10")
		if auth {
			r.AddCookie(login.Result().Cookies()[0])
		}
		Guard(g).ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "192.0.2.1:1000", false); w.Code != 401 {
		t.Fatal("accepted a spoofed identity")
	}
	if w := request("POST", "192.0.2.1:1000", true); w.Code != 403 {
		t.Fatal("accepted POST without CSRF")
	}
	for _, tc := range []struct{ remote, xff string }{{"192.0.2.1:1000", "192.0.2.1"}, {"10.0.0.1:1000", "203.0.113.10, 10.0.0.1"}} {
		w := request("GET", tc.remote, true)
		if w.Code != 200 || w.Body.String() != tc.xff || w.Header().Get("Set-Cookie") != "" || w.Header().Get(AssertionHeader) != "" ||
			w.Header().Get("Strict-Transport-Security") == "" {
			t.Fatalf("unexpected proxy response: %d %s", w.Code, w.Body)
		}
	}
	raw := <-seen
	c.Advance(time.Minute)
	if _, err = verifier.Verify(context.Background(), raw, ""); err == nil {
		t.Fatal("expired gateway assertion accepted")
	}
}

func TestIngressRejection(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		change     func(*http.Request)
		want       int
	}{
		{"CRLF", "/path", func(r *http.Request) { r.Header.Set("X-Test", "a\r\nb") }, 400},
		{"conflicting framing", "/path", func(r *http.Request) { r.Header.Set("Content-Length", "4"); r.TransferEncoding = []string{"chunked"} }, 400},
		{"normalized chunked", "/path", func(r *http.Request) { r.TransferEncoding = []string{"chunked"}; r.ContentLength = -1 }, 400},
		{"body length", "/path", func(r *http.Request) { r.ContentLength = BodyLimit + 1 }, 413},
		{"body read limit", "/path", func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", BodyLimit+1)))
		}, 413},
		{"large header", "/path", func(r *http.Request) { r.Header.Set("X-Test", strings.Repeat("x", HeaderLimit)) }, 400},
		{"encoded slash", "/path%2Ffoo", func(*http.Request) {}, 400},
		{"dot path", "/path/../foo", func(*http.Request) {}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w := httptest.NewRequest("GET", tc.path, nil), httptest.NewRecorder()
			tc.change(r)
			Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("bad request was forwarded") })).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d expected %d", w.Code, tc.want)
			}
		})
	}
}
