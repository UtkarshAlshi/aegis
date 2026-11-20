package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"aegis/internal/audit"
	"aegis/internal/authz"
	"aegis/internal/clock"
	"aegis/internal/jwtx"
	"aegis/internal/session"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const AssertionHeader = "X-Auth-Assertion"
const BodyLimit = 1 << 20
const HeaderLimit = 32 << 10

type Machine func(*http.Request) (session.Identity, error)

type Gateway struct {
	Clock            clock.Clock
	Sessions         *session.Store
	Policy           *authz.Engine
	Signer           *jwtx.Signer
	Issuer, Audience string
	Trusted          []netip.Prefix
	Audit            *audit.Log
	Machine          Machine
	upstream         *httputil.ReverseProxy
}

type outbound struct{ assertion, forwardedFor string }
type outboundKey struct{}

func New(g Gateway, upstream *url.URL) (*Gateway, error) {
	if upstream == nil || g.Clock == nil || g.Sessions == nil || g.Policy == nil || g.Signer == nil || g.Issuer == "" || g.Audience == "" {
		return nil, errors.New("incomplete gateway configuration")
	}
	origin, _ := url.Parse(g.Issuer)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.MaxResponseHeaderBytes = HeaderLimit
	transport.DialContext = (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	g.upstream = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(p *httputil.ProxyRequest) {
			data, _ := p.In.Context().Value(outboundKey{}).(outbound)
			cleanRequestHeaders(p.Out.Header)
			p.SetURL(upstream)
			p.SetXForwarded()
			p.Out.Header.Del("X-Forwarded-Host")
			if origin != nil && origin.Host != "" {
				p.Out.Header.Set("X-Forwarded-Host", origin.Host)
			}
			if data.forwardedFor != "" {
				p.Out.Header.Set("X-Forwarded-For", data.forwardedFor)
			}
			p.Out.Header.Set(AssertionHeader, data.assertion)
		},
		ErrorHandler:   func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "upstream unavailable", 502) },
		ModifyResponse: func(r *http.Response) error { strip(r.Header); r.Header.Del("Set-Cookie"); return nil },
	}
	return &g, nil
}

func cleanRequestHeaders(h http.Header) {
	for k := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Accept", "Accept-Language", "Accept-Encoding", "Content-Type", "Content-Encoding", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "Range", "User-Agent":
		default:
			delete(h, k)
		}
	}
}

func strip(h http.Header) {
	for k := range h {
		lower := strings.ToLower(k)
		for _, prefix := range []string{"x-auth", "x-forwarded", "x-remote", "remote-", "x-user", "x-role", "x-group", "x-identity", "x-client", "x-ssl", "ssl-client", "x-original", "x-rewrite"} {
			if strings.HasPrefix(lower, prefix) {
				delete(h, k)
				break
			}
		}
		switch lower {
		case "authorization", "proxy-authorization", "cookie", "forwarded", "x-csrf-token", "x-real-ip", "x-http-method-override", "x-method-override", "x-http-method", "x-envoy-original-path":
			delete(h, k)
		}
	}
}

func (g *Gateway) forwardedFor(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	trusted := false
	for _, p := range g.Trusted {
		if p.Contains(ip.Unmap()) {
			trusted = true
			break
		}
	}
	if !trusted {
		return ip.String()
	}
	var chain []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(line, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(part))
			if err != nil || addr.Zone() != "" || len(chain) >= 16 {
				return ip.String()
			}
			chain = append(chain, addr.String())
		}
	}
	return strings.Join(append(chain, ip.String()), ", ")
}

func validHeaders(r *http.Request) bool {
	if strings.ContainsAny(r.Host, "\r\n") {
		return false
	}
	cl, te := r.Header.Values("Content-Length"), r.Header.Values("Transfer-Encoding")
	if len(cl) > 1 || (len(cl) > 0 && strings.Contains(cl[0], ",")) || len(r.TransferEncoding) > 0 || len(te) > 0 {
		return false
	}
	size := len(r.Host) + len(r.RequestURI)
	for k, values := range r.Header {
		if strings.ContainsAny(k, "\r\n") {
			return false
		}
		for _, v := range values {
			if strings.ContainsAny(v, "\r\n") {
				return false
			}
			size += len(k) + len(v) + 4
		}
	}
	return size <= HeaderLimit
}

// Guard applies the same ingress checks to protocol endpoints and protected routes.
func Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !validHeaders(r) || r.Method == http.MethodConnect || r.Method == http.MethodTrace || r.Header.Get("Upgrade") != "" ||
			!authz.ValidPath(r.URL.Path) || r.URL.RawPath != "" || r.URL.IsAbs() {
			http.Error(w, "bad request", 400)
			return
		}
		if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
			http.Error(w, "bad query", 400)
			return
		}
		if r.ContentLength > BodyLimit {
			http.Error(w, "body too large", 413)
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			defer r.Body.Close()
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, BodyLimit))
			var overflow *http.MaxBytesError
			if errors.As(err, &overflow) {
				http.Error(w, "body too large", 413)
				return
			}
			if err != nil {
				http.Error(w, "bad body", 400)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.TransferEncoding = nil
			r.Trailer = nil
			r.Header.Del("Content-Length")
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Gateway) Identity(r *http.Request) (session.Identity, string, error) {
	if g.Machine != nil {
		id, err := g.Machine(r)
		if err != nil || id.Subject == "" {
			g.Audit.Event("mtls", "certificate_rejected", false)
			return id, "", errors.New("machine identity unavailable")
		}
		g.Audit.Event("mtls", "certificate_verified", true)
		return id, "", nil
	}
	id, csrf, err := g.Sessions.Authenticate(r)
	if err == nil {
		g.Audit.Event("session", "session_verified", true)
	}
	return id, csrf, err
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, _, err := g.Identity(r)
	if errors.Is(err, session.ErrCSRF) {
		g.Audit.Event("session", "csrf_rejected", false)
		http.Error(w, "forbidden", 403)
		return
	}
	if err != nil {
		if g.Machine == nil {
			g.Audit.Event("session", "authentication_required", false)
		}
		http.Error(w, "authentication required", 401)
		return
	}
	if !g.Policy.Allow(r.URL.Path, r.Method, id) {
		g.Audit.Event(id.Provider, "policy_denied", false)
		http.Error(w, "forbidden", 403)
		return
	}
	now := g.Clock.Now()
	assertion, err := g.Signer.Sign(jwtx.Claims{
		Claims: jwt.Claims{Issuer: g.Issuer, Audience: jwt.Audience{g.Audience}, Subject: id.Subject, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute))},
		Kind:   id.Kind, Provider: id.Provider, Groups: id.Groups, Roles: id.Roles,
	})
	if err != nil {
		http.Error(w, "assertion unavailable", 500)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	g.upstream.ServeHTTP(w, r.WithContext(context.WithValue(ctx, outboundKey{}, outbound{assertion, g.forwardedFor(r)})))
}

func (g *Gateway) JWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{g.Signer.Public}})
}

func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: Guard(h), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: HeaderLimit,
		TLSConfig: TLSConfig()}
}
