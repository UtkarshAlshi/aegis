package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `listen: 127.0.0.1:8443
public_url: https://gateway.example
tls_cert: gateway.crt
tls_key: gateway.key
assertion_key: assertion.key
upstream: http://127.0.0.1:9000
audience: upstream
policy: policy.yaml
trusted_proxies: ["10.0.0.0/8"]
oidc:
  issuer: https://issuer.example
  client_id: gateway
  redirect_uri: https://gateway.example/auth/oidc/callback
`

func TestStrictConfiguration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "aegis.yaml")
	load := func(config string) error {
		t.Helper()
		if err := os.WriteFile(file, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(file)
		return err
	}
	if err := load(validConfig); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]string{
		"unrecognized field":        validConfig + "unknown: true\n",
		"separate document":         validConfig + "---\n{}\n",
		"client redirect mismatch":  strings.Replace(validConfig, "https://gateway.example/auth", "https://other.example/auth", 1),
		"plaintext remote upstream": strings.Replace(validConfig, "127.0.0.1:9000", "other.example", 1),
		"upstream user info":        strings.Replace(validConfig, "127.0.0.1:9000", "user@127.0.0.1:9000", 1),
		"missing assertion key":     strings.Replace(validConfig, "assertion_key: assertion.key", "", 1),
		"invalid CIDR":              strings.Replace(validConfig, "10.0.0.0/8", "anything", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := load(cfg); err == nil {
				t.Fatal("insecure configuration accepted")
			}
		})
	}
}
