# Aegis

Aegis is a Go identity gateway that authenticates browser users with OIDC or SAML and services with mutual TLS. It evaluates an ordered YAML policy and sends a 60-second ES256 identity assertion to a configured upstream. The demo upstream verifies the gateway's signature using its public JWKS.

## Run the demo

Use Go 1.25 or later and Make. Choose a supported, patched Go release. The race suite also needs a working C toolchain. Docker and external identity-provider accounts are unnecessary.

```sh
make demo
```

1. Import the printed demo CA certificate into a disposable browser profile's trusted authorities. Open **https://localhost:8443/** in that profile.
2. Choose **Sign in with OIDC**, then **Continue as alice**. Select **Open protected route** and check that the upstream reports `alice` with provider `oidc`.
3. Sign out and choose **Sign in with SAML**. Continue as **bob**, select **Return to Aegis**, and open the protected route again. The upstream should report `bob` with provider `saml`.
4. Run the `curl --cacert … --cert … --key …` command printed by the demo. It calls the mTLS listener at **https://localhost:8444/protected** and should return `spiffe://aegis/service/robot`.

The demo creates fresh certificates and keys on each run and removes its temporary copy when it shuts down. Discard the temporary browser profile after testing. If a port is busy, run `go run ./cmd/demo -browser-port 0 -machine-port 0` and use the printed URLs.

```sh
go vet ./...
go test -race ./...
go test ./internal/jwtx -run '^$' -fuzz '^FuzzCompactJWT$' -fuzztime 10s -parallel 2
```

## Configure the gateway

```yaml
listen: 0.0.0.0:8443
public_url: https://gateway.example:8443
tls_cert: /etc/aegis/gateway.crt
tls_key: /etc/aegis/gateway.key
assertion_key: /etc/aegis/assertion.key
upstream: https://app.internal
audience: app.internal
policy: /etc/aegis/policy.yaml
trusted_proxies: []
oidc:
  issuer: https://login.example
  client_id: aegis
  redirect_uri: https://gateway.example:8443/auth/oidc/callback
  algorithms: [RS256]
saml:
  entity_id: https://sso.example/metadata
  metadata: /etc/aegis/idp-metadata.xml
mtls:
  listen: 0.0.0.0:8444
  ca: /etc/aegis/client-ca.crt
  revocations: /etc/aegis/revoked.txt
```

- Enable at least one authentication method. The example OIDC client uses `client_id` authentication for a public client. To use `client_secret_basic`, place `client_secret` in a protected config file. Register the exact redirect URI and configure the IdP to emit signed `groups` and `roles` claims where needed.
- Register `/auth/saml/metadata` with the IdP and provision trusted IdP metadata out of band. The SP uses Redirect authentication requests and POST responses with a signed plaintext assertion. Group and role values come from signed SAML attributes named `groups` and `roles`.
- Use a PKCS#8 PEM P-256 private key for assertions and a separate TLS key pair. Give the upstream the gateway's public HTTPS origin, `audience`, and `/.well-known/jwks.json`. Configure it to verify ES256 with those exact issuer and audience values and accept requests only over a restricted upstream network path.
- The browser listener serves `/healthz`, `/readyz`, and aggregate `/metrics`. Limit access to these routes at the deployment boundary if traffic volume or operational status is sensitive. The machine listener requires a client certificate on every connection.

A policy for browser users in `engineering` and the `robot` machine can share a rule. Each listed group and role is required for a browser user. Machine entries are an exact-match list.

```yaml
rules:
  - path_prefix: /protected/admin
    methods: [GET, HEAD]
    deny: true
  - path_prefix: /protected
    methods: [GET, HEAD]
    groups: [engineering]
    machines: ["spiffe://aegis/service/robot"]
```

```sh
go run ./cmd/aegis -config /etc/aegis/aegis.yaml
```

Send `SIGHUP` to the running gateway process on Unix to reload policy and TLS files. TLS key-pair files are also checked once a second. Replace files with complete writes. A failed reload retains the previous valid snapshot.

### Issue a development CA and certificates

```sh
go run ./cmd/aegis-pki init-ca -dir ./local-pki
go run ./cmd/aegis-pki issue server -dir ./local-pki -sans localhost,127.0.0.1
go run ./cmd/aegis-pki issue client -dir ./local-pki -name robot -out robot
go run ./cmd/aegis-pki revoke -dir ./local-pki -cert ./local-pki/robot.crt
```

The gateway reads the CA certificate and revocation file only. Keep the CA private key on the issuing host. Supply the issued leaf in the machine client's certificate file. Clients may also send the configured root.

## Security properties

| Boundary | Enforcement |
| --- | --- |
| Browser login | HTTPS OIDC discovery, exact issuer and redirect URI, S256 PKCE, browser-bound single-use state and nonce. SAML requires a signed assertion, pinned metadata, request correlation, bounded time windows and replay tracking. |
| Browser session | Random server-side ID, rotation on sign-in, `__Host-` cookie flags, 30-minute idle and eight-hour absolute expiry. Unsafe requests require a session CSRF token. |
| Machine identity | TLS 1.2 or newer, verified client chain, explicit ClientAuth EKU, exact service URI SAN and revocation at handshake and request time. |
| Authorization | First rule matching both path prefix and method decides. Segments and methods are exact, and unmatched traffic is denied. |
| Upstream identity | An allowlist controls inbound headers that survive. Aegis supplies forwarding metadata and a 60-second signed assertion. The upstream verifies issuer, audience, signature, and times. |
| Resource limits | 32 KiB application header budget, 1 MiB buffered request bodies, outbound deadlines, bounded claims and login state, browser login rate limits and a bounded JWKS cache. |
| Logging | Fixed reason codes and aggregate counters. Tokens, cookies, assertions and keys are excluded from log payloads. |

## What is tested

- **JWT and JWKS** — unsigned and wrong-algorithm JWTs, invalid signatures, malformed and oversized tokens, remote key headers, issuer/audience/authorized party, subject, nonce, time bounds, unknown and removed keys, concurrent refresh, cache directives and outage limits. The compact parser also has a fuzz target.
- **OIDC** — state and nonce mismatch, invalid PKCE binding, callback and code replay, strict redirect and discovery issuer, generic provider errors, exchange timeout and readiness during outage.
- **Sessions and proxy** — fixation, flags, idle and absolute expiry, CSRF, spoofed identity and forwarding headers, framing conflicts, CR/LF, path ambiguity, limits, valid and expired upstream assertions.
- **SAML** — unsigned and tampered assertions, ambiguous assertion placement, timing, audience, recipient, request ID, issuer, destination, replay, malformed XML and prohibited XML directives.
- **mTLS, policy and operations** — missing, expired, wrong-CA and wrong-EKU certs, incorrect SANs, revocation on new and existing connections, uninterrupted certificate reload, default deny, failed policy reload, configuration rejection and rate limits.
- **End to end** — a TLS client with a cookie jar completes both IdP flows, accesses the protected route, signs out, and confirms the machine route requires mTLS. The upstream checks the assertion against the gateway's published JWKS.

## Limitations

- Sessions, pending logins, rate limits and replay tracking are per process. Multi-replica deployments need shared state or a different routing and replay design. No Redis, LDAP or AD connector, identity provisioning, deb/rpm packaging, or online CA service.
- Logout clears the gateway session only. OIDC provider logout, SAML single logout, encrypted assertions, IdP-initiated sign-in, SAML artifact binding and signed SP authentication requests are outside the supported profile.
- TLS leaf files can rotate live. Changes to assertion signing keys, IdP metadata and the mTLS trust root require a restart. The revocation file is a local serial list. There is no CRL distribution, OCSP or automatic renewal.
- A leaked upstream assertion is usable until its expiry. Protect the hop, isolate the upstream, and avoid logging request headers there. The gateway's demo home and API share an origin with proxied content, so only proxy applications trusted to serve that origin.
- WebSocket upgrades, CONNECT, TRACE, chunked inbound HTTP/1 bodies and arbitrary client headers are outside the proxy contract. The browser login limiter uses the TCP peer, so users behind one proxy share its quota.
- The application clock is injectable for Aegis checks. Crewjam's internal checks also apply and use its process clock. Real browser cookie and TLS behavior is outside Go's cookie-jar simulation.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md), [learning guide](docs/LEARNING.md), and [design decisions](docs/DECISIONS.md).
