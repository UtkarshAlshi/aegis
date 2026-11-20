package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aegis/internal/clock"
	"aegis/internal/oidc"
	"aegis/internal/session"
	"aegis/internal/testidp"
)

func TestOIDCFlow(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     testidp.OIDCMode
		badState bool
		want     int
	}{
		{"happy path and code replay", testidp.OIDCNormal, false, 303},
		{"state mismatch", testidp.OIDCNormal, true, 400},
		{"nonce mismatch", testidp.OIDCWrongNonce, false, 401},
		{"wrong PKCE verifier", testidp.OIDCWrongVerifier, false, 401},
		{"IdP error stays generic", testidp.OIDCError, false, 400},
		{"token exchange timeout", testidp.OIDCTimeout, false, 504},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := clock.NewManual(time.Unix(100000, 0))
			idp, err := testidp.NewOIDC(c, "client", "https://gateway.example/auth/oidc/callback")
			if err != nil {
				t.Fatal(err)
			}
			defer idp.Server.Close()
			idp.SetMode(tc.mode)
			client := idp.Server.Client()
			client.Timeout = 250 * time.Millisecond
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			sessions := session.New(c, time.Minute, time.Hour)
			p, err := oidc.New(context.Background(), c, client, idp.Config(), sessions, nil)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			p.Login(w, httptest.NewRequest("GET", "https://gateway.example/auth/oidc/login", nil))
			cookie := w.Result().Cookies()[0]
			authURL, err := url.Parse(w.Header().Get("Location"))
			if err != nil || authURL.Query().Get("code_challenge_method") != "S256" || len(authURL.Query().Get("code_challenge")) != 43 {
				t.Fatal("invalid authorization redirect")
			}
			auth, err := client.Post(authURL.String(), "application/x-www-form-urlencoded", nil)
			if err != nil {
				t.Fatal(err)
			}
			auth.Body.Close()
			cbURL, err := url.Parse(auth.Header.Get("Location"))
			if err != nil || cbURL.Host != "gateway.example" {
				t.Fatal("invalid callback URL")
			}
			if tc.badState {
				q := cbURL.Query()
				q.Set("state", "wrong")
				cbURL.RawQuery = q.Encode()
			}
			callback := func() *httptest.ResponseRecorder {
				r, w := httptest.NewRequest("GET", cbURL.String(), nil), httptest.NewRecorder()
				r.AddCookie(cookie)
				p.Callback(w, r)
				return w
			}
			result := callback()
			if result.Code != tc.want {
				t.Fatalf("want %d, got %d (%s)", tc.want, result.Code, result.Body)
			}
			if tc.want != 303 {
				if result.Header().Get("Location") != "" || strings.Contains(result.Body.String(), "idp private text") {
					t.Fatal("provider error was reflected")
				}
				return
			}
			if result.Header().Get("Location") != "/" || len(result.Result().Cookies()) != 2 {
				t.Fatal("session was not rotated on login")
			}
			if callback().Code != 400 {
				t.Fatal("replayed callback accepted")
			}
			// Bind an already redeemed code to a fresh pending login.
			w = httptest.NewRecorder()
			p.Login(w, httptest.NewRequest("GET", "https://gateway.example/auth/oidc/login", nil))
			cookie = w.Result().Cookies()[0]
			q := cbURL.Query()
			q.Set("state", cookie.Value)
			cbURL.RawQuery = q.Encode()
			if callback().Code != 401 {
				t.Fatal("redeemed authorization code accepted")
			}
		})
	}
}

func TestOIDCDiscoveryIssuerAndRedirect(t *testing.T) {
	c := clock.Real{}
	p, err := testidp.NewOIDC(c, "client", "https://gateway.example/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Server.Close()
	s := session.New(c, time.Minute, time.Hour)
	cfg := p.Config()
	cfg.RedirectURI += "?redirect=https://other.test/"
	if _, err := oidc.New(context.Background(), c, p.Server.Client(), cfg, s, nil); err == nil {
		t.Fatal("redirect accepted")
	}
	p.SetMode(testidp.OIDCWrongIssuer)
	if _, err := oidc.New(context.Background(), c, p.Server.Client(), p.Config(), s, nil); err == nil {
		t.Fatal("discovery issuer mismatch accepted")
	}
}
