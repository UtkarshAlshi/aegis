package jwtx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"aegis/internal/clock"
	jose "github.com/go-jose/go-jose/v4"
)

// Client copies the transport while imposing a deadline and forbidding redirects.
func Client(base *http.Client) *http.Client {
	c := &http.Client{Timeout: 3 * time.Second}
	if base != nil {
		c.Transport = base.Transport
		if base.Timeout > 0 && base.Timeout < c.Timeout {
			c.Timeout = base.Timeout
		}
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func ReadJSON(r *http.Response, limit int64, dst any) error {
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", r.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if int64(len(raw)) > limit {
		return errors.New("response too large")
	}
	return json.Unmarshal(raw, dst)
}

type Cache struct {
	clock         clock.Clock
	client        *http.Client
	url           string
	maxStale      time.Duration
	mu            sync.Mutex
	keys          map[string]jose.JSONWebKey
	expires, next time.Time
	failure       error
	flight        chan struct{}
}

func NewCache(c clock.Clock, client *http.Client, endpoint string, maxStale time.Duration) *Cache {
	return &Cache{clock: c, client: Client(client), url: endpoint, maxStale: maxStale}
}

func (c *Cache) Warm(ctx context.Context) error {
	_, err := c.get(ctx, "", true)
	return err
}

func (c *Cache) Lookup(ctx context.Context, kid, alg string) (any, error) {
	key, err := c.get(ctx, kid, false)
	if err != nil {
		return nil, err
	}
	if key.Algorithm != "" && key.Algorithm != alg {
		return nil, errors.New("JWK algorithm mismatch")
	}
	return key.Key, nil
}

func (c *Cache) get(ctx context.Context, kid string, warm bool) (jose.JSONWebKey, error) {
	var refreshed bool
	for {
		c.mu.Lock()
		now := c.clock.Now()
		key, found := c.keys[kid]
		fresh := c.keys != nil && now.Before(c.expires)
		if fresh && (found || warm) && c.flight == nil {
			c.mu.Unlock()
			return key, nil
		}
		if c.flight != nil {
			done := c.flight
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return key, ctx.Err()
			case <-done:
			}
			refreshed = true
			continue
		}
		if refreshed || now.Before(c.next) {
			stale := found && c.failure != nil && now.Before(c.expires.Add(c.maxStale))
			err := c.failure
			c.mu.Unlock()
			if found && (fresh || stale || (refreshed && err == nil)) || warm && refreshed && err == nil {
				return key, nil
			}
			if err != nil {
				return key, err
			}
			return key, errors.New("JWKS key unavailable")
		}
		c.flight = make(chan struct{})
		c.mu.Unlock()

		keys, ttl, err := c.fetch(ctx)
		c.mu.Lock()
		now = c.clock.Now()
		c.failure = err
		c.next = now.Add(time.Second)
		if err == nil {
			c.keys = keys
			c.expires = now.Add(ttl)
			// An expired set may refresh immediately, even after an unknown-kid refresh.
			if ttl > 0 && ttl < time.Second {
				c.next = c.expires
			}
		}
		close(c.flight)
		c.flight = nil
		c.mu.Unlock()
		refreshed = true
	}
}

func (c *Cache) fetch(ctx context.Context) (map[string]jose.JSONWebKey, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	var set jose.JSONWebKeySet
	if err = ReadJSON(res, 256<<10, &set); err != nil {
		return nil, 0, err
	}
	keys := make(map[string]jose.JSONWebKey)
	seen := make(map[string]bool)
	for _, key := range set.Keys {
		if key.KeyID == "" {
			continue
		}
		if seen[key.KeyID] {
			return nil, 0, errors.New("duplicate JWKS key ID")
		}
		seen[key.KeyID] = true
		if !key.IsPublic() || !key.Valid() || (key.Use != "" && key.Use != "sig") {
			continue
		}
		if !matches(key.Key, "RS256") && !matches(key.Key, "ES256") && !matches(key.Key, "EdDSA") {
			continue
		}
		keys[key.KeyID] = key
	}
	return keys, cacheTTL(res.Header), nil
}

func cacheTTL(h http.Header) time.Duration {
	ttl := int64(300)
	for _, value := range h.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(name) {
			case "no-cache", "no-store", "must-revalidate":
				if name != "must-revalidate" {
					return 0
				}
			case "max-age":
				n, err := strconv.ParseInt(strings.Trim(arg, "\""), 10, 64)
				if err == nil && n >= 0 {
					ttl = min(ttl, n)
				}
			}
		}
	}
	if age, err := strconv.ParseInt(h.Get("Age"), 10, 64); err == nil && age > 0 {
		ttl = max(0, ttl-age)
	}
	return time.Duration(ttl) * time.Second
}
