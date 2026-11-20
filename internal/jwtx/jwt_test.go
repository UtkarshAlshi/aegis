package jwtx

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aegis/internal/clock"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func signKey(t *testing.T) *Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
func testClaims() Claims {
	return Claims{Claims: jwt.Claims{Issuer: "issuer", Audience: jwt.Audience{"client"}, Subject: "alice",
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Hour)), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}, Nonce: "nonce"}
}
func signed(t *testing.T, s *Signer, c Claims) string {
	t.Helper()
	raw, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestJWTClaims(t *testing.T) {
	s := signKey(t)
	v, err := NewVerifier(clock.NewManual(now), "issuer", "client", nil, s.Lookup, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Claims)
		valid  bool
	}{
		{"valid", func(*Claims) {}, true},
		{"wrong issuer", func(c *Claims) { c.Issuer = "issuer/" }, false},
		{"wrong audience", func(c *Claims) { c.Audience = jwt.Audience{"other"} }, false},
		{"wrong authorized party", func(c *Claims) { c.AuthorizedParty = "other" }, false},
		{"multi audience missing azp", func(c *Claims) { c.Audience = append(c.Audience, "other") }, false},
		{"empty subject", func(c *Claims) { c.Subject = "" }, false},
		{"missing expiry", func(c *Claims) { c.Expiry = nil }, false},
		{"missing iat", func(c *Claims) { c.IssuedAt = nil }, false},
		{"future iat", func(c *Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(time.Minute + time.Second)) }, false},
		{"expired", func(c *Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-time.Hour)) }, false},
		{"skew inside", func(c *Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-59 * time.Second)) }, true},
		{"skew boundary", func(c *Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-60 * time.Second)) }, false},
		{"not before inside skew", func(c *Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Minute)) }, true},
		{"future nbf", func(c *Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Minute + time.Second)) }, false},
		{"wrong nonce", func(c *Claims) { c.Nonce = "other" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClaims()
			tc.change(&c)
			_, err := v.Verify(context.Background(), signed(t, s, c), "nonce")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
		})
	}
	bad := 5*time.Minute + time.Second
	if _, err := NewVerifier(clock.NewManual(now), "issuer", "client", &bad, s.Lookup, jose.ES256); err == nil {
		t.Fatal("accepted excessive leeway")
	}
}

func TestJWTHeaders(t *testing.T) {
	s := signKey(t)
	raw := signed(t, s, testClaims())
	parts := strings.Split(raw, ".")
	reheader := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + parts[1] + "." + parts[2]
	}
	v, err := NewVerifier(clock.NewManual(now), "issuer", "client", nil, s.Lookup, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"none":                      reheader(`{"alg":"none","kid":"key"}`),
		"HS256 with asymmetric kid": reheader(`{"alg":"HS256","kid":"` + s.Public.KeyID + `"}`),
		"garbage":                   "???", "truncated": parts[0] + "." + parts[1], "oversized": strings.Repeat("a", MaxToken+1),
		"invalid signature": parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), token, "nonce"); err == nil {
				t.Fatal("accepted malformed token")
			}
		})
	}
}
func TestJWTIgnoresRemoteKeyHeaders(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithHeader("kid", "trusted").WithHeader("jku", server.URL).WithHeader("x5u", server.URL).WithHeader("jwk", jose.JSONWebKey{Key: signKey(t).Public.Key})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(testClaims()).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(clock.NewManual(now), "issuer", "client", nil, func(_ context.Context, kid, alg string) (any, error) { return &k.PublicKey, nil }, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Verify(context.Background(), raw, "nonce"); err != nil || hits.Load() != 0 {
		t.Fatalf("unexpected verification result: %v", err)
	}
}

func TestJWKSRotationAndOutage(t *testing.T) {
	old, next := signKey(t), signKey(t)
	var state, hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=10")
		switch state.Load() {
		case 0:
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{old.Public}})
		case 1:
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{next.Public}})
		case 2:
			http.Error(w, "down", 503)
		case 3:
			_, _ = w.Write([]byte(strings.Repeat("x", 257<<10)))
		}
	}))
	defer srv.Close()
	c := clock.NewManual(now)
	cache := NewCache(c, nil, srv.URL, 20*time.Second)
	v, err := NewVerifier(c, "issuer", "client", nil, cache.Lookup, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	first, second := signed(t, old, testClaims()), signed(t, next, testClaims())
	unknown := signed(t, signKey(t), testClaims())
	check := func(raw string, want bool) {
		t.Helper()
		_, err := v.Verify(context.Background(), raw, "nonce")
		if (err == nil) != want {
			t.Fatalf("expected valid=%v, got %v", want, err)
		}
	}
	check(first, true)
	check(unknown, false)
	if hits.Load() != 1 {
		t.Fatal("unknown kid bypassed rate limit")
	}
	c.Advance(time.Second)
	state.Store(1)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), second, "nonce"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 2 {
		t.Fatalf("rotation fetched %d times", hits.Load())
	}
	check(first, false)
	state.Store(2)
	c.Advance(9 * time.Second)
	check(second, true)
	if hits.Load() != 2 {
		t.Fatal("fresh set was fetched early")
	}
	c.Advance(time.Second)
	check(second, true)
	c.Advance(20 * time.Second)
	check(second, false)
	c.Advance(time.Second)
	state.Store(3)
	check(second, false)
}
func FuzzCompactJWT(f *testing.F) {
	f.Add("invalid")
	f.Add("e30.e30.e30")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parse(s, []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.EdDSA})
	})
}

func TestJWKSCacheDirectivesAndReadiness(t *testing.T) {
	for _, tc := range []struct {
		control string
		age     string
		ttl     time.Duration
		stale   bool
	}{
		{"public, max-age=600", "10", 590 * time.Second, true},
		{"max-age=99999", "", time.Hour, true},
		{"max-age=10, must-revalidate", "", 10 * time.Second, false},
		{"MAX-AGE=600, NO-STORE", "", 0, false},
		{"no-cache", "", 0, false},
		{"max-age=2", "10", 0, true},
	} {
		h := http.Header{}
		h.Set("Cache-Control", tc.control)
		h.Set("Age", tc.age)
		p := readCachePolicy(h)
		if p.ttl != tc.ttl || p.allowStale != tc.stale {
			t.Errorf("%q: unexpected TTL or stale status %v", tc.control, p)
		}
	}
	key := signKey(t)
	var unavailable atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Cache-Control", "max-age=1, must-revalidate")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.Public}})
	}))
	defer srv.Close()
	c := clock.NewManual(now)
	ctx := context.Background()
	mismatched := NewCache(c, nil, srv.URL, time.Minute, jose.RS256)
	if mismatched.Warm(ctx) == nil {
		t.Fatal("readiness accepted unusable signing algorithm")
	}
	cache := NewCache(c, nil, srv.URL, time.Minute, jose.ES256)
	if err := cache.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	unavailable.Store(true)
	c.Advance(time.Second)
	if cache.Warm(ctx) == nil {
		t.Fatal("readiness accepted an expired key set")
	}
	if _, err := cache.Lookup(ctx, key.Public.KeyID, "ES256"); err == nil {
		t.Fatal("must-revalidate returned stale key")
	}
}

func TestAllowedAsymmetricJWTAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		alg             jose.SignatureAlgorithm
		private, public any
	}{
		{jose.RS256, rsaKey, &rsaKey.PublicKey},
		{jose.EdDSA, edKey, edPub},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			s, err := jose.NewSigner(jose.SigningKey{Algorithm: tc.alg, Key: tc.private}, (&jose.SignerOptions{}).WithHeader("kid", "actual"))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := jwt.Signed(s).Claims(testClaims()).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			lookup := func(_ context.Context, kid, alg string) (any, error) {
				if kid != "actual" || alg != string(tc.alg) {
					t.Error("incorrect protected key selection")
				}
				return tc.public, nil
			}
			v, err := NewVerifier(clock.NewManual(now), "issuer", "client", nil, lookup, jose.RS256, jose.EdDSA)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.Verify(context.Background(), raw, "nonce"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
