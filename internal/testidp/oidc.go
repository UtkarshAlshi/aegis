// Package testidp contains loopback-only demo identity providers.
package testidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"aegis/internal/clock"
	"aegis/internal/jwtx"
	"aegis/internal/oidc"
	"aegis/internal/session"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type OIDCMode int

const (
	OIDCNormal OIDCMode = iota
	OIDCWrongIssuer
	OIDCWrongNonce
	OIDCWrongVerifier
	OIDCError
	OIDCTimeout
)

type code struct {
	challenge, nonce string
	expires          time.Time
}

type OIDC struct {
	Server                *httptest.Server
	ClientID, RedirectURI string
	clock                 clock.Clock
	signer                *jwtx.Signer
	mu                    sync.Mutex
	mode                  OIDCMode
	codes                 map[string]code
}

var login = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Demo OIDC</title><h1>Demo OIDC</h1><form method="post"><button>Continue as alice (engineering)</button></form></html>`))

func NewOIDC(c clock.Clock, clientID, redirect string) (*OIDC, error) {
	return NewOIDCTLS(c, clientID, redirect, nil)
}

func NewOIDCTLS(c clock.Clock, clientID, redirect string, transport *tls.Config) (*OIDC, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := jwtx.NewSigner(key)
	if err != nil {
		return nil, err
	}
	p := &OIDC{clock: c, ClientID: clientID, RedirectURI: redirect, signer: signer, codes: make(map[string]code)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /keys", p.keys)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewUnstartedServer(mux)
	p.Server.TLS = transport
	p.Server.StartTLS()
	return p, nil
}

func (p *OIDC) SetMode(m OIDCMode) { p.mu.Lock(); defer p.mu.Unlock(); p.mode = m }
func (p *OIDC) Mode() OIDCMode     { p.mu.Lock(); defer p.mu.Unlock(); return p.mode }
func (p *OIDC) Config() oidc.Config {
	return oidc.Config{Issuer: p.Server.URL, ClientID: p.ClientID, RedirectURI: p.RedirectURI, Algorithms: []jose.SignatureAlgorithm{jose.ES256}}
}

func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (p *OIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	issuer := p.Server.URL
	if p.Mode() == OIDCWrongIssuer {
		issuer += "/other"
	}
	respond(w, oidc.Discovery{Issuer: issuer, Authorization: p.Server.URL + "/authorize", Token: p.Server.URL + "/token", JWKS: p.Server.URL + "/keys", Challenges: []string{"S256"}})
}
func (p *OIDC) keys(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "max-age=60")
	respond(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.signer.Public}})
}
func (p *OIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("redirect_uri") != p.RedirectURI || q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("nonce") == "" || q.Get("state") == "" {
		http.Error(w, "invalid authorization request", 400)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = login.Execute(w, nil)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	key, err := session.Random()
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	p.mu.Lock()
	now := p.clock.Now()
	for k, v := range p.codes {
		if !now.Before(v.expires) {
			delete(p.codes, k)
		}
	}
	if len(p.codes) >= 4096 {
		p.mu.Unlock()
		http.Error(w, "unavailable", 503)
		return
	}
	p.codes[key] = code{q.Get("code_challenge"), q.Get("nonce"), now.Add(time.Minute)}
	p.mu.Unlock()
	u, _ := url.Parse(p.RedirectURI)
	args := url.Values{"state": {q.Get("state")}, "code": {key}}
	if p.Mode() == OIDCError {
		args = url.Values{"state": {q.Get("state")}, "error": {"access_denied"}, "error_description": {"idp private text"}}
	}
	u.RawQuery = args.Encode()
	http.Redirect(w, r, u.String(), 303)
}
func (p *OIDC) consume(r *http.Request) (code, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := r.PostForm.Get("code")
	record, ok := p.codes[key]
	delete(p.codes, key)
	if !ok || !p.clock.Now().Before(record.expires) {
		return code{}, errors.New("invalid code")
	}
	return record, nil
}
func (p *OIDC) token(w http.ResponseWriter, r *http.Request) {
	mode := p.Mode()

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != p.ClientID || r.PostForm.Get("redirect_uri") != p.RedirectURI {
		http.Error(w, "invalid grant", 400)
		return
	}
	if mode == OIDCTimeout {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
		case <-timer.C:
		}
		return
	}

	record, err := p.consume(r)
	secret := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(secret))
	if err != nil || len(secret) < 43 || len(secret) > 128 || base64.RawURLEncoding.EncodeToString(sum[:]) != record.challenge || mode == OIDCWrongVerifier {
		http.Error(w, "invalid grant", 400)
		return
	}
	now := p.clock.Now()
	if mode == OIDCWrongNonce {
		record.nonce = "different"
	}
	raw, err := p.signer.Sign(jwtx.Claims{Claims: jwt.Claims{Issuer: p.Server.URL, Audience: jwt.Audience{p.ClientID}, Subject: "alice",
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))}, Nonce: record.nonce, Groups: []string{"engineering"}})
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	respond(w, map[string]string{"id_token": raw, "token_type": "Bearer", "access_token": "demo-unused"})
}
