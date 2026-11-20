package session

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aegis/internal/clock"
)

func TestSessionRotationCookieCSRFAndExpiry(t *testing.T) {
	c := clock.NewManual(time.Unix(1000, 0))
	s := New(c, time.Minute, 3*time.Minute)
	login := func(previous *http.Cookie) *http.Cookie {
		t.Helper()
		r, w := httptest.NewRequest("GET", "https://gateway/", nil), httptest.NewRecorder()
		if previous != nil {
			r.AddCookie(previous)
		}
		if err := s.Login(w, r, Identity{Subject: "alice"}); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0]
	}
	fake := &http.Cookie{Name: Cookie, Value: "attacker"}
	first := login(fake)
	actual := login(first)
	data, err := base64.RawURLEncoding.DecodeString(actual.Value)
	if err != nil || len(data) != 32 || actual.Value == first.Value || first.Value == fake.Value ||
		actual.Name != "__Host-aegis" || actual.Path != "/" || actual.Domain != "" ||
		!actual.Secure || !actual.HttpOnly || actual.SameSite != http.SameSiteLaxMode || actual.MaxAge != 180 {
		t.Fatalf("incorrect cookie attributes")
	}
	request := func(m string, cookie *http.Cookie, csrf string) (string, error) {
		r := httptest.NewRequest(m, "https://gateway/", nil)
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		_, token, err := s.Authenticate(r)
		return token, err
	}
	for _, bad := range []*http.Cookie{fake, first} {
		if _, err := request("GET", bad, ""); err == nil {
			t.Fatal("fixed session accepted")
		}
	}
	csrf, err := request("GET", actual, "")
	if err != nil || csrf == "" {
		t.Fatal("missing valid CSRF token")
	}
	if _, err = request("POST", actual, "wrong"); !errors.Is(err, ErrCSRF) {
		t.Fatal("bad CSRF accepted")
	}
	if _, err = request("POST", actual, csrf); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		c.Advance(50 * time.Second)
		if _, err = request("GET", actual, ""); err != nil {
			t.Fatal("active session expired early")
		}
	}
	c.Advance(30 * time.Second)
	if _, err = request("GET", actual, ""); err == nil {
		t.Fatal("absolute expiry ignored")
	}
	idle := login(nil)
	c.Advance(time.Minute)
	if _, err = request("GET", idle, ""); err == nil {
		t.Fatal("idle expiry ignored")
	}
}
