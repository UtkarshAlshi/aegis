package samlx_test

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"aegis/internal/clock"
	"aegis/internal/pki"
	"aegis/internal/samlx"
	"aegis/internal/session"
	"aegis/internal/testidp"
)

var field = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

func TestSignedSAMLFlow(t *testing.T) {
	c := clock.NewManual((clock.Real{}).Now())
	root, err := pki.NewCA(c, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.ParseCA(c, root)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ca.IssueServer([]string{"127.0.0.1"}, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	idp, err := testidp.NewSAML(c, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Server.Close()
	metadata, err := idp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	sessions := session.New(c, time.Minute, time.Hour)
	sp, err := samlx.New(c, "https://sp.example", idp.EntityID(), metadata, sessions, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err = sp.MetadataXML()
	if err != nil || !idp.RegisterSP(metadata) {
		t.Fatalf("SP metadata registration failed: %v", err)
	}

	for _, tc := range []struct {
		name string
		mode testidp.SAMLMode
		want int
	}{
		{"valid and replay", testidp.SAMLNormal, 303},
		{"unsigned assertion", testidp.SAMLUnsignedAssertion, 401},
		{"tampered signed content", testidp.SAMLTampered, 401},
		{"ambiguous assertion layout", testidp.SAMLAmbiguous, 401},
		{"expired outside gateway leeway", testidp.SAMLExpired, 401},
		{"wrong audience", testidp.SAMLWrongAudience, 401},
		{"wrong recipient", testidp.SAMLWrongRecipient, 401},
		{"wrong InResponseTo", testidp.SAMLWrongInResponseTo, 401},
		{"wrong issuer", testidp.SAMLWrongIssuer, 401},
		{"wrong destination", testidp.SAMLWrongDestination, 401},
		{"malformed XML", testidp.SAMLMalformed, 401},
		{"XML entity directives prohibited", testidp.SAMLDirective, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp.SetMode(tc.mode)
			w := httptest.NewRecorder()
			sp.Login(w, httptest.NewRequest("GET", "/auth/saml/login", nil))
			cookies := w.Result().Cookies()
			if w.Code != 303 || len(cookies) != 1 || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteNoneMode {
				t.Fatalf("invalid SAML login response %d", w.Code)
			}
			res, err := idp.Server.Client().Get(w.Header().Get("Location") + "&demo=1")
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			matches := field.FindAllSubmatch(body, -1)
			if res.StatusCode != 200 || len(matches) != 2 {
				t.Fatalf("invalid IdP response %d", res.StatusCode)
			}
			form := url.Values{}
			for _, m := range matches {
				form.Set(string(m[1]), html.UnescapeString(string(m[2])))
			}
			callback := func(cookie *http.Cookie) *httptest.ResponseRecorder {
				r, w := httptest.NewRequest("POST", "/auth/saml/acs", strings.NewReader(form.Encode())), httptest.NewRecorder()
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if cookie != nil {
					r.AddCookie(cookie)
				}
				sp.ACS(w, r)
				return w
			}
			if tc.want == 303 && callback(nil).Code != 400 {
				t.Fatal("accepted response without relay cookie")
			}
			result := callback(cookies[0])
			if result.Code != tc.want {
				t.Fatalf("status %d expected %d", result.Code, tc.want)
			}
			if tc.want == 303 {
				loginCookies := result.Result().Cookies()
				if len(loginCookies) != 2 {
					t.Fatal("no browser session")
				}
				r := httptest.NewRequest("GET", "/", nil)
				r.AddCookie(loginCookies[1])
				identity, _, err := sessions.Authenticate(r)
				if err != nil || identity.Subject != "bob" || identity.Provider != "saml" || len(identity.Groups) != 1 || identity.Groups[0] != "engineering" {
					t.Fatalf("invalid SAML identity: %v", err)
				}
				if callback(cookies[0]).Code != 400 {
					t.Fatal("accepted reused relay state")
				}
			}
		})
	}
}
