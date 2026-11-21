package jwtx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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
	algorithms    []jose.SignatureAlgorithm
	mu            sync.Mutex
	keys          map[string]jose.JSONWebKey
	expires, next time.Time
	staleAllowed  bool
	failure       error
	flight        chan struct{}
}

func NewCache(c clock.Clock, client *http.Client, endpoint string, maxStale time.Duration, algs ...jose.SignatureAlgorithm) *Cache {
	return &Cache{clock: c, client: Client(client), url: endpoint, maxStale: min(5*time.Minute, max(0, maxStale)), algorithms: slices.Clone(algs)}
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
		// A refresh for an unfamiliar key must not stall requests using fresh keys.
		if fresh && (found || (warm && len(c.keys) != 0)) {
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
		if refreshed || (now.Before(c.next) && (c.failure != nil || (!found && !warm))) {
			stale := found && c.staleAllowed && c.failure != nil && now.Before(c.expires.Add(c.maxStale))
			err := c.failure
			usable := len(c.keys) != 0
			c.mu.Unlock()
			if found && (fresh || stale || (refreshed && err == nil)) || warm && refreshed && err == nil && usable {
				return key, nil
			}
			if err != nil {
				return key, err
			}
			return key, errors.New("JWKS key unavailable")
		}
		c.flight = make(chan struct{})
		c.mu.Unlock()

		keys, policy, err := c.fetch(ctx)
		c.mu.Lock()
		now = c.clock.Now()
		c.failure = err
		c.next = now.Add(time.Second)
		if err == nil {
			c.keys = keys
			c.expires = now.Add(policy.ttl)
			c.staleAllowed = policy.allowStale
		}
		close(c.flight)
		c.flight = nil
		c.mu.Unlock()
		refreshed = true
	}
}

func (c *Cache) fetch(ctx context.Context) (map[string]jose.JSONWebKey, cachePolicy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, cachePolicy{}, err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, cachePolicy{}, err
	}
	var set jose.JSONWebKeySet
	if err = ReadJSON(res, 256<<10, &set); err != nil {
		return nil, cachePolicy{}, err
	}
	keys := make(map[string]jose.JSONWebKey)
	seen := make(map[string]bool)
	for _, key := range set.Keys {
		if key.KeyID == "" {
			continue
		}
		if seen[key.KeyID] {
			return nil, cachePolicy{}, errors.New("duplicate JWKS key ID")
		}
		seen[key.KeyID] = true
		if !key.IsPublic() || !key.Valid() || (key.Use != "" && key.Use != "sig") {
			continue
		}
		supported := c.algorithms
		if len(supported) == 0 {
			supported = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}
		}
		if !slices.ContainsFunc(supported, func(alg jose.SignatureAlgorithm) bool {
			return (key.Algorithm == "" || key.Algorithm == string(alg)) && matches(key.Key, string(alg))
		}) {
			continue
		}
		keys[key.KeyID] = key
	}
	return keys, readCachePolicy(res.Header), nil
}

type cachePolicy struct {
	ttl        time.Duration
	allowStale bool
}

func readCachePolicy(h http.Header) cachePolicy {
	const defaultTTL = 300
	const maxTTL = 3600
	ttl := int64(defaultTTL)
	var hasTTL, immediate bool
	allowStale := true
	for _, value := range h.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-cache", "no-store":
				allowStale = false
				immediate = true
			case "must-revalidate":
				allowStale = false
			case "max-age":
				n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(arg), "\""), 10, 64)
				if err == nil && n >= 0 {
					if !hasTTL {
						ttl = maxTTL
					}
					hasTTL = true
					ttl = min(ttl, n)
				}
			}
		}
	}
	if immediate {
		ttl = 0
	}
	if age, err := strconv.ParseInt(h.Get("Age"), 10, 64); err == nil && age > 0 {
		ttl = max(0, ttl-age)
	}
	return cachePolicy{time.Duration(ttl) * time.Second, allowStale}
}
