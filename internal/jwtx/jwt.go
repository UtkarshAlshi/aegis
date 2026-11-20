package jwtx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"aegis/internal/clock"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const MaxToken = 16 << 10

type Claims struct {
	jwt.Claims
	Nonce           string   `json:"nonce,omitempty"`
	AuthorizedParty string   `json:"azp,omitempty"`
	Groups          []string `json:"groups,omitempty"`
	Roles           []string `json:"roles,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	Provider        string   `json:"provider,omitempty"`
}

type Lookup func(context.Context, string, string) (any, error)

type Verifier struct {
	clock            clock.Clock
	issuer, audience string
	leeway           time.Duration
	algs             []jose.SignatureAlgorithm
	lookup           Lookup
}

// A nil leeway defaults to one minute. An explicit zero is useful at the upstream.
func NewVerifier(c clock.Clock, issuer, audience string, leeway *time.Duration, lookup Lookup, algorithms ...jose.SignatureAlgorithm) (*Verifier, error) {
	skew := time.Minute
	if leeway != nil {
		skew = *leeway
	}
	if c == nil || issuer == "" || audience == "" || lookup == nil || skew < 0 || skew > 5*time.Minute || len(algorithms) == 0 {
		return nil, errors.New("invalid verifier configuration")
	}
	for _, a := range algorithms {
		switch a {
		case jose.RS256, jose.ES256, jose.EdDSA:
		default:
			return nil, errors.New("unsupported JWT algorithm")
		}
	}
	return &Verifier{c, issuer, audience, skew, slices.Clone(algorithms), lookup}, nil
}

func parse(raw string, algorithms []jose.SignatureAlgorithm) (*jose.JSONWebSignature, error) {
	if len(raw) == 0 || len(raw) > MaxToken || strings.Count(raw, ".") != 2 || strings.ContainsAny(raw, " \r\n\t") || strings.HasPrefix(raw, "{") {
		return nil, errors.New("invalid compact JWT")
	}
	return jose.ParseSignedCompact(raw, algorithms)
}

func (v *Verifier) Verify(ctx context.Context, raw, nonce string) (Claims, error) {
	var c Claims
	token, err := parse(raw, v.algs)
	if err != nil || len(token.Signatures) != 1 {
		return c, errors.New("invalid JWT header")
	}
	h := token.Signatures[0].Protected
	if h.KeyID == "" || len(h.KeyID) > 256 {
		return c, errors.New("invalid key ID")
	}
	key, err := v.lookup(ctx, h.KeyID, h.Algorithm)
	if err != nil || !matches(key, h.Algorithm) {
		return c, errors.New("JWT key unavailable")
	}
	payload, err := token.Verify(key)
	if err != nil {
		return c, errors.New("invalid JWT signature")
	}
	if json.Unmarshal(payload, &c) != nil {
		return Claims{}, errors.New("invalid JWT claims")
	}
	now := v.clock.Now()
	if c.Issuer != v.issuer || !slices.Contains(c.Audience, v.audience) || strings.TrimSpace(c.Subject) == "" ||
		c.Expiry == nil || c.IssuedAt == nil ||
		!now.Before(c.Expiry.Time().Add(v.leeway)) || c.IssuedAt.Time().After(now.Add(v.leeway)) ||
		!c.IssuedAt.Time().Before(c.Expiry.Time()) ||
		(c.NotBefore != nil && (c.NotBefore.Time().After(now.Add(v.leeway)) || !c.NotBefore.Time().Before(c.Expiry.Time()))) ||
		(nonce != "" && c.Nonce != nonce) ||
		(c.AuthorizedParty != "" && c.AuthorizedParty != v.audience) || (len(c.Audience) > 1 && c.AuthorizedParty != v.audience) {
		return Claims{}, errors.New("JWT claims rejected")
	}
	return c, nil
}

func matches(key any, alg string) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && k != nil && k.N != nil && k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return alg == "ES256" && k != nil && k.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return alg == "EdDSA" && len(k) == ed25519.PublicKeySize
	default:
		return false
	}
}

type Signer struct {
	signer jose.Signer
	Public jose.JSONWebKey
}

func NewSigner(key *ecdsa.PrivateKey) (*Signer, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("ES256 requires P-256")
	}
	pub := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256", Use: "sig"}
	hash, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(hash)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", pub.KeyID))
	if err != nil {
		return nil, err
	}
	return &Signer{signer, pub}, nil
}

func (s *Signer) Sign(c Claims) (string, error) {
	raw, err := jwt.Signed(s.signer).Claims(c).Serialize()
	if err != nil {
		return "", err
	}
	if len(raw) > MaxToken {
		return "", errors.New("signed token exceeds size limit")
	}
	return raw, nil
}

func (s *Signer) Lookup(_ context.Context, kid, alg string) (any, error) {
	if kid != s.Public.KeyID || alg != s.Public.Algorithm {
		return nil, errors.New("unknown signing key")
	}
	return s.Public.Key, nil
}
