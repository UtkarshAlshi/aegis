# Threat model

## Assets and trust boundaries

Sensitive assets include assertion-signing keys, TLS and CA keys, OIDC client secrets, ID tokens, SAML assertions, pending login state, session IDs, CSRF tokens, policy, revocation state and verified identity data.

Browsers, machines and all ingress headers are untrusted at entry. Configured IdPs are trusted to authenticate browser users and issue group and role membership. The dedicated client CA is trusted to issue service identities. Operators control config, trusted proxy addresses, policy, key files and metadata. The upstream consumes gateway-signed identity and is trusted to serve content on the application's origin. The demo uses a loopback hop and production can use HTTPS upstream.

## STRIDE

The tests name the behavior they exercise. Tests establish a regression check for the cited mitigation within the implemented profile.

| STRIDE | Threat | Mitigation | Exact test |
| --- | --- | --- | --- |
| Spoofing | Attacker provides identity or forwarding headers. | Authenticate locally, allowlist client headers, reconstruct forwarding metadata and issue a signed assertion. | `TestProxyIdentityAndAssertion`, `TestDemoThroughHTTPS` |
| Spoofing | JWT presents an unsigned or symmetric algorithm, invalid signature, foreign issuer, wrong audience or wrong nonce. | Pin asymmetric algorithms and key types, verify signatures before checking the claims. | `TestJWTHeaders`, `TestJWTClaims`, `TestAllowedAsymmetricJWTAlgorithms` |
| Spoofing | Stolen browser code or callback URL is redeemed with a different login context. | Require single-use browser-bound state, retain the verifier server-side, and compare the nonce after signature verification. | `TestOIDCFlow/state_mismatch`, `TestOIDCFlow/wrong_PKCE_verifier`, `TestOIDCFlow/nonce_mismatch`, `TestOIDCFlow/happy_path_and_code_replay` |
| Spoofing | Machine claims an identity with an expired, wrong-CA, wrong-EKU or wrong-SAN certificate. | Verify the dedicated chain and exact client profile during TLS establishment. | `TestMTLSHandshakeAndRevocation` |
| Tampering | Proxy sees ambiguous HTTP framing, header values or paths. | Reject conflicting framing, all incoming transfer encodings, CR/LF and noncanonical paths. | `TestIngressRejection/conflicting_framing`, `TestIngressRejection/normalized_chunked`, `TestIngressRejection/CRLF`, `TestIngressRejection/encoded_slash`, `TestIngressRejection/dot_path` |
| Tampering | SAML changes signed content, supplies an unsigned assertion, nests extra assertions, or supplies XML entity directives. | Require one scoped signed assertion, verify actual signed content and prohibit XML directives. | `TestSignedSAMLFlow/unsigned_assertion`, `TestSignedSAMLFlow/tampered_signed_content`, `TestSignedSAMLFlow/ambiguous_assertion_layout`, `TestSignedSAMLFlow/XML_entity_directives_prohibited`, `TestXMLStructureGuards` |
| Tampering | Invalid policy is uploaded during reload. | Strictly parse a bounded candidate and atomically publish only on success. | `TestPolicyMatrixAndBadReload` |
| Repudiation | A denied login attempt leaves no operator-visible signal. | Emit fixed reason codes and count authentication events. | `TestBrowserRateLimitAndReadiness`, `TestDemoThroughHTTPS` |
| Information disclosure | A remote key header triggers a verifier fetch, or IdP error text reaches the browser. | Select keys from configured JWKS only and use generic browser responses. | `TestJWTIgnoresRemoteKeyHeaders`, `TestOIDCFlow/IdP_error_stays_generic`, `TestBrowserRateLimitAndReadiness` |
| Information disclosure | Browser credentials or assertion leak through forwarding or the upstream response. | Keep cookies and browser authorization at ingress and strip assertion-related response headers. | `TestProxyIdentityAndAssertion` |
| Denial of service | Burst of unknown key IDs or IdP/JWKS outage causes fan-out or indefinite retries. | Coalesce JWKS refreshes, throttle misses, enforce deadlines and bound stale use. | `TestJWKSRotationAndOutage`, `TestJWKSCacheDirectivesAndReadiness`, `TestOIDCFlow/token_exchange_timeout`, `TestOIDCReadinessRejectsUnavailableOrDriftedProvider` |
| Denial of service | Oversized HTTP or JWT input and login bursts occupy gateway resources. | Limit headers, bodies and tokens, and cap login requests per peer. | `TestIngressRejection`, `TestJWTHeaders/oversized`, `FuzzCompactJWT`, `TestBrowserRateLimitAndReadiness` |
| Elevation of privilege | Session fixation, CSRF, or old session reuse grants access. | Rotate and invalidate IDs, enforce expiry and require a session-specific CSRF secret on unsafe methods. | `TestSessionRotationCookieCSRFAndExpiry`, `TestProxyIdentityAndAssertion`, `TestDemoThroughHTTPS` |
| Elevation of privilege | SAML assertion is replayed or used for a different SP or request. | Bind the relay cookie, pending request, signed bearer recipient, audience and timing. Reserve the verified assertion ID. | `TestSignedSAMLFlow`, `TestAssertionReplayStore` |
| Elevation of privilege | Revoked client remains authorized or unlisted principals reach the upstream. | Read revocations at handshake and request time and enforce a first-match, default-deny policy. | `TestMTLSHandshakeAndRevocation`, `TestPolicyMatrixAndBadReload` |
| Elevation of privilege | An intermediary replays an expired gateway assertion. | Use a 60-second ES256 assertion and zero verification leeway in the demo upstream. | `TestProxyIdentityAndAssertion` |

## Residual risks

A trusted IdP, signing-key holder, CA operator, or privileged host process can issue or manipulate identities within its authority. Revocation affects subsequent handshakes and requests. A request already admitted can finish. Upstream assertions remain bearer credentials until expiry, and the upstream should be reachable only over the intended network path. Aegis has bounded per-process protections against resource exhaustion, while aggregate traffic limits, reliable telemetry retention and distributed revocation remain deployment concerns.
