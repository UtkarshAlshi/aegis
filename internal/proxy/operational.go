package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"aegis/internal/clock"
)

const rateWindow = time.Minute
const maxRatePeers = 8192
const requestsPerWindow = 30

type rateBucket struct {
	requests int
	until    time.Time
}

type loginLimiter struct {
	clock       clock.Clock
	mu          sync.Mutex
	peers       map[netip.Addr]rateBucket
	nextCleanup time.Time
}

func (l *loginLimiter) allow(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap().WithZone("")
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.nextCleanup) {
		for k, v := range l.peers {
			if !now.Before(v.until) {
				delete(l.peers, k)
			}
		}
		l.nextCleanup = now.Add(rateWindow)
	}
	b, exists := l.peers[ip]
	if !exists && len(l.peers) >= maxRatePeers {
		return false
	}
	if !now.Before(b.until) {
		b = rateBucket{until: now.Add(rateWindow)}
	}
	if b.requests >= requestsPerWindow {
		return false
	}
	b.requests++
	l.peers[ip] = b
	return true
}

func (g *Gateway) BrowserHandler(mux *http.ServeMux, ready func(context.Context) error) http.Handler {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		defer cancel()
		if ready != nil && ready(ctx) != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var success, failure uint64
		if g.Audit != nil {
			success = g.Audit.Success.Load()
			failure = g.Audit.Failure.Load()
		}
		_, _ = fmt.Fprintf(w, "# TYPE aegis_auth_events_total counter\naegis_auth_events_total{outcome=\"success\"} %d\naegis_auth_events_total{outcome=\"failure\"} %d\n", success, failure)
	})
	limiter := &loginLimiter{clock: g.Clock, peers: make(map[netip.Addr]rateBucket)}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/oidc/login", "/auth/oidc/callback", "/auth/saml/login", "/auth/saml/acs":
			if !limiter.allow(r.RemoteAddr) {
				g.Audit.Event("browser", "rate_limited", false)
				w.Header().Set("Retry-After", "60")
				http.Error(w, "sign-in unavailable", 429)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
