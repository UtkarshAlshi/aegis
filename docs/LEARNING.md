# Learning guide

## Follow an identity through Aegis

**OIDC code and PKCE.** Aegis asks the IdP to authenticate a user. The browser returns carrying a short-lived authorization code. Aegis redeems the code directly with the IdP. Before redirecting the browser, Aegis hashes a private random verifier and sends the resulting S256 challenge. The IdP checks that the verifier supplied at redemption matches that challenge. State binds the browser's callback to its pending login. The nonce binds the resulting signed ID token to that same login.

**JWT validation.** Aegis limits input size, accepts compact JWS and inspects the protected algorithm and key ID. It selects a trusted public key compatible with the algorithm and verifies the signature. It then checks issuer, audience, subject, expiry, issued-at, optional not-before and, for OIDC login, the expected nonce. A signature authenticates the bytes. The claims say whether those bytes apply to this party and transaction.

**JWKS rotation.** A JWKS is a published public key set. During rollover, the signer can publish both keys before signing with a new key ID. A verifier can refresh on a miss and pick up the new key. An authoritative refresh replaces its key set, so a removed key stops working. A bounded stale window applies during eligible outages. A revalidation directive can disable that fallback.

**SAML SP-initiated login.** Aegis sends an AuthnRequest with a unique ID to the IdP. After authentication, the browser posts a signed assertion to the Assertion Consumer Service. Aegis binds the browser's relay value and pending request ID, then checks the signature, issuer, audience, recipient, destination and validity period. It tracks the assertion ID to reject reuse.

**XML signature wrapping.** An XML signature authenticates a referenced element. A parser and verifier can disagree about which element has meaning if the document carries ambiguous IDs, nested assertions or unexpected namespaces. Aegis requires one direct assertion and one assertion-level signature referencing it, disallows ambiguous layouts, and takes identity from the assertion returned by the verifier.

**mTLS and revocation.** In regular HTTPS the server proves possession of its TLS private key. Mutual TLS adds proof of possession from the client. Aegis verifies the client with its internal CA, requires the ClientAuth purpose and maps a URI SAN to a service identity. Adding a serial to the revocation file blocks that certificate at the next handshake or request even if the leaf's validity period has time left.

## Interview questions

| # | Question | Short answer |
| --- | --- | --- |
| 1 | What does Aegis do after authentication? | It applies route policy, strips untrusted headers and signs the authorized identity for the upstream. |
| 2 | Why use Authorization Code flow? | Aegis exchanges the code on its back channel and keeps the ID token out of browser URLs. |
| 3 | How does PKCE bind an authorization code? | The IdP compares the recorded S256 challenge with the hash of the verifier supplied at redemption. |
| 4 | What does OIDC state protect? | It binds the callback to a particular browser and pending login, and is consumed once. |
| 5 | What does nonce protect? | It binds the signed ID token to the original authentication request. |
| 6 | Why validate issuer and audience after verifying the signature? | A token can have a valid signature and still originate from the wrong issuer or be intended for a different application. |
| 7 | How do you prevent JWT algorithm confusion? | Pin an asymmetric algorithm allowlist and require the matching public-key type. |
| 8 | Can a token choose its own verification keys? | Aegis treats the key ID as a lookup hint within the configured issuer's key set and ignores token-supplied key URLs and keys. |
| 9 | What happens when a new signing key appears? | An unknown key ID can trigger one coordinated refresh, subject to a cooldown. |
| 10 | What happens when an issuer removes a key? | The next successful JWKS refresh replaces the whole set and removes that key from verification. |
| 11 | Why allow stale keys during an outage? | The bounded fallback lets an existing known key work briefly when the provider is down. It delays seeing key removal during that period. |
| 12 | Why use a server-side session? | Aegis can revoke an opaque session immediately and enforce idle and absolute deadlines without passing IdP tokens to the browser. |
| 13 | How do session cookies and CSRF checks work together? | Cookie flags constrain delivery and script access. Unsafe requests also need the session's CSRF secret. |
| 14 | Where does SAML request correlation happen? | The gateway compares the pending AuthnRequest ID with the response and the signed bearer confirmation. |
| 15 | Why require a signed assertion? | That signature covers the identity, attributes and bearer confirmation that Aegis uses to create a session. |
| 16 | How do you prevent assertion replay? | Consume pending state once and remember accepted assertion IDs for their remaining admissible lifetime. |
| 17 | What differentiates ClientAuth and a service URI SAN? | ClientAuth permits the certificate for client TLS authentication. The URI SAN names the service the application authorizes. |
| 18 | How does certificate rotation avoid dropping connections? | A replacement key pair is published atomically for new handshakes while active connections retain their established TLS state. |
| 19 | What happens if a policy reload fails? | The candidate is discarded and the previous validated rules continue to decide requests. |
| 20 | What would you change for multiple replicas? | Share session, pending and replay state, distribute revocation consistently, and coordinate signing-key rollover. |

## References

- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636, Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8725, JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [RFC 5280, Internet X.509 Public Key Infrastructure](https://www.rfc-editor.org/rfc/rfc5280)
