# Architecture

`cmd/aegis` composes the production listeners, policy and provider configuration. `cmd/demo` runs the same protocol handlers with in-process identity providers and a separate verifying upstream HTTP listener. Human and machine traffic share policy and assertion signing.

```mermaid
flowchart TD
  Browser["Browser"] --> Human["Browser HTTPS listener"]
  Machine["Service client"] --> TLS["mTLS listener"]
  Human --> Login["OIDC RP / SAML SP"]
  Login <-->|"Discovery, proof and keys"| IdP["Configured identity providers"]
  Login --> Session["Browser session store"]
  Human --> Session
  Session --> Policy["Ordered default-deny policy"]
  TLS -->|"Verified SPIFFE URI"| Policy
  Policy --> Signer["Gateway assertion signer"]
  Signer --> Upstream["Verifying upstream"]
  Upstream -->|"Public signing keys"| Human
```

## OIDC login

```mermaid
sequenceDiagram
  participant B as Browser
  participant G as Aegis
  participant I as OIDC IdP
  B->>G: Start login
  G-->>B: Set pending cookie and redirect
  B->>I: Authorize with S256 challenge and nonce
  I-->>B: Redirect with code and state
  B->>G: Send code, state and pending cookie
  G->>I: Exchange code with verifier and fixed redirect URI
  I-->>G: Return signed ID token
  opt Key set expires or kid is unknown
    G->>I: Fetch configured JWKS
  end
  G->>G: Verify signature, claims and nonce
  G-->>B: Rotate session and redirect home
```

## SAML login

```mermaid
sequenceDiagram
  participant B as Browser
  participant G as Aegis SP
  participant I as SAML IdP
  B->>G: Start SP login
  G-->>B: Set relay cookie and redirect
  B->>I: Send AuthnRequest and RelayState
  I-->>B: Return assertion form
  B->>G: POST response, RelayState and relay cookie
  G->>G: Bind request, validate signature and claims
  G->>G: Reserve assertion ID and rotate session
  G-->>B: Redirect home
```

The relay cookie is available to a cross-site POST. The longer-lived browser session uses SameSite=Lax. Aegis remembers the old session ID with the pending SAML request so it can retire that session even when the ACS request omits the old cookie.

## Machine request

```mermaid
sequenceDiagram
  participant C as Service client
  participant G as Aegis mTLS listener
  participant A as Upstream
  C->>G: Establish TLS using client certificate
  G->>G: Verify CA, EKU, URI SAN and revocation
  C->>G: Request protected route
  G->>G: Recheck certificate and apply policy
  G->>A: Send request with signed identity
  A->>G: Fetch public JWKS on demand
  A->>A: Verify signature, issuer, audience and expiry
  A-->>G: Return response
  G-->>C: Return response
```

The application does not trust ingress-supplied identities. Trusted proxy CIDRs only affect the forwarded address chain. Attached headers and cookies cannot establish a machine or human identity. The public JWKS contains only the assertion key's public portion.
