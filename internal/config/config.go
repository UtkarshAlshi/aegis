package config

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"

	"aegis/internal/oidc"
	"gopkg.in/yaml.v3"
)

type SAML struct {
	EntityID string `yaml:"entity_id"`
	Metadata string `yaml:"metadata"`
}

type MTLS struct {
	Listen      string `yaml:"listen"`
	CA          string `yaml:"ca"`
	Revocations string `yaml:"revocations"`
}

type Config struct {
	Listen         string         `yaml:"listen"`
	PublicURL      string         `yaml:"public_url"`
	TLSCert        string         `yaml:"tls_cert"`
	TLSKey         string         `yaml:"tls_key"`
	AssertionKey   string         `yaml:"assertion_key"`
	Upstream       string         `yaml:"upstream"`
	Audience       string         `yaml:"audience"`
	Policy         string         `yaml:"policy"`
	TrustedProxies []netip.Prefix `yaml:"trusted_proxies"`
	OIDC           *oidc.Config   `yaml:"oidc"`
	SAML           *SAML          `yaml:"saml"`
	MTLS           *MTLS          `yaml:"mtls"`
}

func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return cfg, errors.New("configuration unavailable or too large")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid configuration YAML")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("expected one configuration document")
	}
	return cfg, cfg.Validate()
}

func (cfg Config) Validate() error {
	if _, port, err := net.SplitHostPort(cfg.Listen); err != nil || port == "" {
		return errors.New("invalid listen address")
	}
	base, err := oidc.SecureURL(cfg.PublicURL)
	if err != nil || base.Path != "" || base.RawQuery != "" || base.ForceQuery {
		return errors.New("public_url must be an HTTPS origin")
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" || cfg.AssertionKey == "" || cfg.Policy == "" || cfg.Audience == "" {
		return errors.New("TLS, assertion key, policy and audience are required")
	}
	if cfg.OIDC != nil && cfg.OIDC.RedirectURI != cfg.PublicURL+"/auth/oidc/callback" {
		return errors.New("OIDC redirect URI must match public_url")
	}
	if cfg.OIDC == nil && cfg.SAML == nil && cfg.MTLS == nil {
		return errors.New("at least one authentication method is required")
	}
	if cfg.SAML != nil && (cfg.SAML.Metadata == "" || cfg.SAML.EntityID == "") {
		return errors.New("SAML metadata and entity ID required")
	}
	if cfg.MTLS != nil {
		if _, port, err := net.SplitHostPort(cfg.MTLS.Listen); err != nil || port == "" || cfg.MTLS.Listen == cfg.Listen || cfg.MTLS.CA == "" || cfg.MTLS.Revocations == "" {
			return errors.New("invalid mTLS listener configuration")
		}
	}
	_, err = UpstreamURL(cfg.Upstream)
	return err
}

func UpstreamURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Opaque != "" || u.Path != "" {
		return nil, errors.New("upstream must be an origin")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if u.Scheme != "http" || err != nil || !ip.IsLoopback() {
		return nil, errors.New("upstream must use HTTPS or a loopback IP")
	}
	return u, nil
}
