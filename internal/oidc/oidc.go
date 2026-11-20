package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"aegis/internal/audit"
	"aegis/internal/clock"
	"aegis/internal/jwtx"
	"aegis/internal/session"
	jose "github.com/go-jose/go-jose/v4"
)

const pendingCookie = "__Host-aegis-oidc"
const pendingTTL = 5 * time.Minute

type Config struct {
	Issuer       string                    `yaml:"issuer"`
	ClientID     string                    `yaml:"client_id"`
	ClientSecret string                    `yaml:"client_secret"`
	RedirectURI  string                    `yaml:"redirect_uri"`
	Algorithms   []jose.SignatureAlgorithm `yaml:"algorithms"`
}

type Discovery struct {
	Issuer        string   `json:"issuer"`
	Authorization string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	JWKS          string   `json:"jwks_uri"`
	Challenges    []string `json:"code_challenge_methods_supported"`
}

type flow struct{ verifier, nonce string }
type RP struct {
	cfg       Config
	discovery Discovery
	pending   *session.Pending[flow]
	sessions  *session.Store
	client    *http.Client
	cache     *jwtx.Cache
	verify    *jwtx.Verifier
	audit     *audit.Log
}

func SecureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid HTTPS URL")
	}
	return u, nil
}

func New(ctx context.Context, c clock.Clock, client *http.Client, cfg Config, s *session.Store, a *audit.Log) (*RP, error) {
	issuer, err := SecureURL(cfg.Issuer)
	if err != nil || issuer.ForceQuery || issuer.RawQuery != "" || cfg.ClientID == "" || s == nil || c == nil {
		return nil, errors.New("invalid OIDC configuration")
	}
	redirect, err := SecureURL(cfg.RedirectURI)
	if err != nil || redirect.Path != "/auth/oidc/callback" || redirect.RawQuery != "" || redirect.ForceQuery || redirect.RawPath != "" {
		return nil, errors.New("invalid OIDC redirect URI")
	}
	client = jwtx.Client(client)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.Issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("OIDC discovery unavailable")
	}
	var d Discovery
	if jwtx.ReadJSON(res, 64<<10, &d) != nil || d.Issuer != cfg.Issuer {
		return nil, errors.New("OIDC discovery rejected")
	}
	for _, endpoint := range []string{d.Authorization, d.Token, d.JWKS} {
		if _, err := SecureURL(endpoint); err != nil {
			return nil, err
		}
	}
	if len(d.Challenges) > 0 && !slices.Contains(d.Challenges, "S256") {
		return nil, errors.New("issuer does not support S256")
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []jose.SignatureAlgorithm{jose.RS256}
	}
	cache := jwtx.NewCache(c, client, d.JWKS, 5*time.Minute)
	verifier, err := jwtx.NewVerifier(c, cfg.Issuer, cfg.ClientID, nil, cache.Lookup, cfg.Algorithms...)
	if err != nil {
		return nil, err
	}
	return &RP{cfg, d, session.NewPending[flow](c, pendingTTL), s, client, cache, verifier, a}, nil
}

func (p *RP) Ready(ctx context.Context) error { return p.cache.Warm(ctx) }

func (p *RP) fail(w http.ResponseWriter, reason string, status int) {
	p.audit.Event("oidc", reason, false)
	http.Error(w, "sign-in failed", status)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (p *RP) Login(w http.ResponseWriter, r *http.Request) {
	state, e1 := session.Random()
	verifier, e2 := session.Random()
	nonce, e3 := session.Random()
	if e1 != nil || e2 != nil || e3 != nil || p.pending.Add(state, flow{verifier, nonce}) != nil {
		p.fail(w, "state_unavailable", http.StatusServiceUnavailable)
		return
	}
	session.SetCookie(w, pendingCookie, state, pendingTTL, http.SameSiteLaxMode)
	u, _ := url.Parse(p.discovery.Authorization)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("scope", "openid")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge(verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (p *RP) Callback(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q["state"]) != 1 {
		p.fail(w, "state_invalid", 400)
		return
	}
	flow, ok := p.pending.Take(r, pendingCookie, q.Get("state"))
	if !ok {
		p.fail(w, "state_invalid", 400)
		return
	}
	session.SetCookie(w, pendingCookie, "", -1, http.SameSiteLaxMode)
	if q.Has("error") || len(q["code"]) != 1 || q.Get("code") == "" || (q.Has("iss") && (len(q["iss"]) != 1 || q.Get("iss") != p.cfg.Issuer)) {
		p.fail(w, "authorization_rejected", 400)
		return
	}
	raw, err := p.exchange(r.Context(), q.Get("code"), flow.verifier)
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			p.fail(w, "idp_timeout", 504)
			return
		}
		p.fail(w, "exchange_rejected", 401)
		return
	}
	claims, err := p.verify.Verify(r.Context(), raw, flow.nonce)
	if err != nil {
		p.fail(w, "id_token_rejected", 401)
		return
	}
	id := session.Identity{Subject: claims.Subject, Kind: "user", Provider: "oidc", Groups: claims.Groups, Roles: claims.Roles}
	if err = p.sessions.Login(w, r, id); err != nil {
		p.fail(w, "session_unavailable", 503)
		return
	}
	p.audit.Event("oidc", "login", true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *RP) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.cfg.RedirectURI}, "code_verifier": {verifier}}
	if p.cfg.ClientSecret == "" {
		form.Set("client_id", p.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.discovery.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	res, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	var payload struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err = jwtx.ReadJSON(res, 64<<10, &payload); err != nil {
		return "", err
	}
	if payload.Error != "" || payload.IDToken == "" {
		return "", errors.New("token response rejected")
	}
	return payload.IDToken, nil
}
