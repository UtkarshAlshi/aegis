package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aegis/internal/audit"
	"aegis/internal/clock"
)

func TestBrowserRateLimitAndReadiness(t *testing.T) {
	c := clock.NewManual(time.Unix(100000, 0))
	g := &Gateway{Clock: c, Audit: &audit.Log{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/oidc/login", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(303) })
	handler := g.BrowserHandler(mux, func(context.Context) error { return errors.New("sensitive upstream detail") })
	request := func(path, peer string) *httptest.ResponseRecorder {
		r, w := httptest.NewRequest("GET", path, nil), httptest.NewRecorder()
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "127.0.0.2")
		handler.ServeHTTP(w, r)
		return w
	}
	for range requestsPerWindow {
		if w := request("/auth/oidc/login", "127.0.0.1:1234"); w.Code != 303 {
			t.Fatal("blocked within rate limit")
		}
	}
	if w := request("/auth/oidc/login", "127.0.0.1:2345"); w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("rate limit can be bypassed with a new port")
	}
	if w := request("/auth/oidc/login", "127.0.0.2:2345"); w.Code != 303 {
		t.Fatal("separate peer was blocked")
	}
	c.Advance(time.Minute)
	if w := request("/auth/oidc/login", "127.0.0.1:2345"); w.Code != 303 {
		t.Fatal("rate limit never expired")
	}
	if w := request("/readyz", "127.0.0.1:2345"); w.Code != 503 || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatal("readiness leaked its upstream failure")
	}
	if g.Audit.Failure.Load() != 1 {
		t.Fatal("missing rate-limit audit event")
	}
}
