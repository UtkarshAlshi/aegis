package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"aegis/internal/clock"
)

const Cookie = "__Host-aegis"

type Identity struct {
	Subject, Kind, Provider string
	Groups, Roles           []string
}

type record struct {
	Identity
	csrf          string
	created, last time.Time
}

type Store struct {
	mu             sync.Mutex
	clock          clock.Clock
	idle, absolute time.Duration
	sessions       map[string]record
}

func New(c clock.Clock, idle, absolute time.Duration) *Store {
	return &Store{clock: c, idle: idle, absolute: absolute, sessions: make(map[string]record)}
}

func Random() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func token(r *http.Request, name string) string {
	var value string
	var found bool
	for _, c := range r.Cookies() {
		if c.Name != name {
			continue
		}
		if found {
			return ""
		}
		value, found = c.Value, true
	}
	return value
}

func SetCookie(w http.ResponseWriter, name, value string, ttl time.Duration, sameSite http.SameSite) {
	age := int(ttl / time.Second)
	if ttl < 0 {
		age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: sameSite, MaxAge: age})
}

func (s *Store) expired(entry record, now time.Time) bool {
	return !now.Before(entry.last.Add(s.idle)) || !now.Before(entry.created.Add(s.absolute))
}

func (s *Store) Login(w http.ResponseWriter, r *http.Request, id Identity) error {
	sid, err := Random()
	if err != nil {
		return err
	}
	csrf, err := Random()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	delete(s.sessions, token(r, Cookie))
	if len(s.sessions) >= 10000 {
		for k, v := range s.sessions {
			if s.expired(v, now) {
				delete(s.sessions, k)
			}
		}
		if len(s.sessions) >= 10000 {
			return errors.New("session capacity reached")
		}
	}
	id.Groups = slices.Clone(id.Groups)
	id.Roles = slices.Clone(id.Roles)
	s.sessions[sid] = record{id, csrf, now, now}
	SetCookie(w, Cookie, sid, s.absolute, http.SameSiteLaxMode)
	return nil
}

func safe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

var ErrCSRF = errors.New("CSRF token rejected")

// Authenticate updates the idle deadline only after successful CSRF validation.
func (s *Store) Authenticate(r *http.Request) (Identity, string, error) {
	key := token(r, Cookie)
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[key]
	now := s.clock.Now()
	if !ok || s.expired(value, now) {
		delete(s.sessions, key)
		return Identity{}, "", errors.New("no active session")
	}
	if !safe(r.Method) && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(value.csrf)) != 1 {
		return Identity{}, "", ErrCSRF
	}
	value.last = now
	s.sessions[key] = value
	value.Groups = slices.Clone(value.Groups)
	value.Roles = slices.Clone(value.Roles)
	return value.Identity, value.csrf, nil
}

func (s *Store) Logout(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	delete(s.sessions, token(r, Cookie))
	s.mu.Unlock()
	SetCookie(w, Cookie, "", -1, http.SameSiteLaxMode)
}

// Pending binds a browser cookie to single-use server-side login state.
type Pending[T any] struct {
	mu      sync.Mutex
	clock   clock.Clock
	ttl     time.Duration
	entries map[string]pendingValue[T]
}

type pendingValue[T any] struct {
	value   T
	expires time.Time
}

func NewPending[T any](c clock.Clock, ttl time.Duration) *Pending[T] {
	return &Pending[T]{clock: c, ttl: ttl, entries: make(map[string]pendingValue[T])}
}

func (p *Pending[T]) Add(key string, value T) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock.Now()
	for k, e := range p.entries {
		if !now.Before(e.expires) {
			delete(p.entries, k)
		}
	}
	if len(p.entries) >= 4096 {
		return errors.New("pending login capacity reached")
	}
	p.entries[key] = pendingValue[T]{value, now.Add(p.ttl)}
	return nil
}

func (p *Pending[T]) Take(r *http.Request, name, key string) (T, bool) {
	var zero T
	if key == "" || subtle.ConstantTimeCompare([]byte(token(r, name)), []byte(key)) != 1 {
		return zero, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	value, ok := p.entries[key]
	delete(p.entries, key)
	if !ok || !p.clock.Now().Before(value.expires) {
		return zero, false
	}
	return value.value, true
}
