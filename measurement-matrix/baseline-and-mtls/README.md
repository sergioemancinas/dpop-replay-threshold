# Conditions C0 and M1

**Status: executed. 24 assertions passed, 0 failed. See `results/assertions.txt`.** No latency was measured.

Two conditions from the matrix in `../../PROTOCOL.md` section 3:

- **C0**, the bearer baseline. The control.
- **M1**, RFC 8705 mutual-TLS certificate-bound access tokens.

Correctness assertions only. No latency, no load, no capacity numbers. The
statistical pipeline in `../../PROTOCOL.md` section 5 does not apply: every
assertion here has a binary outcome.

## What each condition claims

**C0.** A bearer token is a pure bearer instrument. Whoever holds it can use it,
from any TLS client identity or from none. This is not a bug being demonstrated,
it is RFC 6750 working as specified, and it is the threat that sender constraining
exists to remove. C0 exists so that M1's rejections have something to be measured
against. If C0's replay assertions fail, the control is not a control and M1 proves
nothing.

**M1.** Keycloak authenticates the client with `tls_client_auth` and issues an
access token carrying `cnf["x5t#S256"]`. The same token that C0 shows to be freely
replayable is admitted only over the certificate it is bound to.

## Assertions

Run by `test/assertions.py`. The table groups related checks; the script emits 24
PASS/FAIL lines, and the numbering below is what the rest of this document refers to.

| # | Condition | Assertion | Expected |
|---|-----------|-----------|----------|
| 1 | C0 | `bearer-client` obtains a token | 200, `token_type: Bearer` |
| 2 | C0 | token carries no `cnf` claim | absent |
| 3 | C0 | accepted over client certificate A | 200 |
| 4 | C0 | replayed over a **different** certificate B | 200 |
| 5 | C0 | replayed with **no** client certificate | 200 |
| 6 | C0 | garbage token, tampered signature | 401 |
| 7 | C0 | unbound token at `/api/bound` | 403 |
| 8 | M1 | `mtls-client` authenticates with certificate A | 200 |
| 9 | M1 | `mtls-client` with certificate B | 401 |
| 10 | M1 | `mtls-client` with no certificate | 401 |
| 11 | M1 | token carries `cnf["x5t#S256"]` | present |
| 12 | M1 | thumbprint equals base64url(SHA-256(DER(client-a))) | equal |
| 13 | M1 | presented over bound certificate A | 200 |
| 14 | M1 | presented over different certificate B | 401 |
| 15 | M1 | presented with no client certificate | 401 |
| 16 | M1 | accepted at `/api/bound`, echoes the thumbprint | 200 |

Assertions 4, 5, 14 and 15 are the comparison the pair exists to make: identical
request shapes, opposite outcomes.

## Running

Certificates are generated at run time and are gitignored. Nothing in this
directory is a credential for any real system, and no private key is committed
where it could be mistaken for one.

```
./certs/gen-certs.sh
docker compose up -d --build
python3 test/assertions.py
```

`docker compose up` fails with a bind-mount error if `gen-certs.sh` has not been
run: `certs/generated/` does not exist in a fresh clone. That is intentional.

Requires `python3` with `httpx`. An explicit `ssl.SSLContext` is used rather than
`verify=<path>` and `cert=<tuple>`, both of which httpx 0.28 deprecated.

### Ports

| Service | Host | Container |
|---------|------|-----------|
| Keycloak, HTTPS | 9443 | 8443 |
| Resource server, HTTPS | 9444 | 8444 |

8080, 8081 and 9000 belong to `../../single-host-validation/` and are avoided.
Keycloak's plain-HTTP listener stays on the compose network and is not published;
the resource server fetches the JWK set over it, which is why no TLS trust anchor
has to be injected into the resource server's JVM. Same split as the D1 stack.

## Design decisions that carry the result

**`https-client-auth=request`, not `required`.** C0 must reach the same token
endpoint with no client certificate. `required` would refuse that connection during
the handshake and C0 could not run against this listener.

**Resource server `client-auth: want`, not `need`.** This is load-bearing. Under
`need`, Tomcat aborts the handshake when no certificate is offered, and assertion 15
would prove only that the socket refused the peer. Under `want` the request reaches
the application, so the 401 is attributable to RFC 8705 section 3.1 token validation,
which is the claim under test.

**One CA signing both client certificates.** Certificate B must pass the TLS
handshake. If B were signed by an untrusted CA, assertion 14 would fail at the
transport and would not be evidence about token binding at all.

**Single-RDN subject DNs.** Keycloak canonicalises both the configured
`x509.subjectdn` and the presented certificate through
`X500Principal.getName(RFC2253)`. RFC 2253 emits RDNs in reverse DER order, so a
multi-RDN subject makes the exact string required in the realm export depend on
encoder ordering. `CN=mtls-client` removes the ambiguity. Verified: the generated
certificate's RFC 2253 subject is exactly `CN=mtls-client`.

**`x509.allow.regex.pattern.comparison: "false"`, set explicitly.** Keycloak
defaults this to `true` when the attribute is absent, which selects regex matching
on a deprecated DN accessor. `false` selects the exact RFC 8705 comparison. The
default is the wrong one for this experiment and silence would not have selected it.

**`client_credentials` for M1, direct grant for C0.** M1 needs no resource owner;
the client certificate carries the identity. Keycloak binds the thumbprint in
`OAuth2GrantTypeBase.checkAndBindMtlsHoKToken`, reached by both grants.

## The RFC 8705 check is Spring Security's, not ours

The resource server contains no thumbprint comparison code. Spring Security 6.5.5
already performs it: `NimbusJwtDecoder` defaults its validator to
`JwtValidators.createDefault()`, which includes the package-private
`org.springframework.security.oauth2.jwt.X509CertificateThumbprintValidator`. That
validator reads `jakarta.servlet.request.X509Certificate`, computes
base64url(SHA-256(DER)) and compares it against `cnf["x5t#S256"]`. Spring Boot's
`OAuth2ResourceServerJwtConfiguration` composes on top of `createDefaultWithIssuer`,
so the check survives autoconfiguration.

Two properties of that validator matter to a reviewer, and both are asserted rather
than worked around:

1. **It fails open on an absent claim, and closed on an unmatchable one.** The two
   cases must not be conflated. If `cnf["x5t#S256"]` is present and no certificate is
   available, it returns `invalid_token`: that is fail-closed, and it is what
   assertion 15 rests on. If the claim is absent entirely, it returns success: that is
   fail-open, and it means a plain bearer token is admitted by an endpoint a deployer
   believes is mTLS-protected. Only the second case is a silent binding failure of the
   kind the paper's taxonomy covers. Assertion 5 exhibits it on the default endpoint;
   assertion 7 shows what an explicit guard costs, which is nine lines in `/api/bound`.
   `../xfcc-silent-binding/` describes the same validator and reaches the same
   conclusions independently.
2. **There is no public API.** The class, its constructor and its
   `Supplier<X509Certificate>` are all package-private. The binding can be inherited
   but not configured, and setting a custom `jwtDecoder` or a hand-built
   `DelegatingOAuth2TokenValidator` silently removes it. The security configuration
   here therefore deliberately does not touch the validator chain.

`/api/bound` returns 403 rather than 401 to keep "you are not sender-constrained"
distinguishable from "your binding does not match".

## Verified against primary sources

Checked before implementing, not assumed.

**RFC 8705** (<https://www.rfc-editor.org/rfc/rfc8705.html>)

- Section 3.1: "The value of the `x5t#S256` member is a base64url-encoded SHA-256
  hash (a.k.a., thumbprint, fingerprint, or digest) of the DER encoding of the X.509
  certificate. The base64url-encoded value MUST omit all trailing pad characters and
  MUST NOT include line breaks, whitespace, or other additional characters." The
  digest is over the whole DER certificate, not the public key.
- Section 3: requests "MUST be made over a mutually authenticated TLS connection
  using the same certificate that was used for mutual TLS at the token endpoint",
  and the protected resource "MUST verify that the certificate matches the
  certificate associated with the access token".
- Section 2.1: `tls_client_auth` is the PKI method, so client certificates chain to
  a CA the authorization server trusts. A literally self-signed client certificate
  would be section 2.2 `self_signed_tls_client_auth`, which Keycloak does not
  implement; there is no such authenticator in the source. Hence the local CA.

**Keycloak 26.6.1** (source at tag `26.6.1`, plus <https://www.keycloak.org/server/mutual-tls>,
`/server/enabletls`, `/server/keycloak-truststore`)

- `X509ClientAuthenticator.PROVIDER_ID` is `client-x509`; attribute keys are
  `x509.subjectdn` and `x509.allow.regex.pattern.comparison`.
- `OIDCConfigAttributes.USE_MTLS_HOK_TOKEN` is
  `tls.client.certificate.bound.access.tokens`. Admin Console label: "OAuth 2.0
  Mutual TLS Certificate Bound Access Tokens Enabled".
- `MtlsHoKTokenUtil` computes `Base64Url.encode(SHA-256(cert.getEncoded()))` and
  writes it to `AccessToken.Confirmation` as JSON `cnf` / `x5t#S256`, matching
  RFC 8705 section 3.1.
- `--https-client-auth` takes `none|request|required`. `--https-trust-store-file`
  was deprecated in 24 and 25 and **undeprecated in 26.0**; it is current in 26.6.1.
  A `.pem` file needs no password: Quarkus `TlsUtils.computeTrustOptions` infers the
  type from the extension and returns `PemTrustOptions` before reaching the password
  check. Left unset, mTLS client validation falls back to the system truststore,
  which trusts the whole JRE CA bundle, so it is set explicitly.
- `start-dev` force-enables plain HTTP but does not disable the HTTPS listener; it
  comes up because certificate material is configured. `https-client-auth` is a
  build-time option, auto-applied under `start-dev`.
- The `quarkus` `X509ClientCertificateLookup` provider (`order() = 100`) is selected
  automatically, so direct TLS termination needs no `--spi-x509cert-lookup-*` option.
  Those are for reverse-proxy header forwarding, which belongs to conditions X1/X2.
- Client authentication failure returns **401** `invalid_client` for both a missing
  and a mismatched certificate: `X509ClientAuthenticator` calls `context.attempted()`
  in both cases, `ClientAuthenticationFlow` raises
  `GENERIC_AUTHENTICATION_ERROR`, and `AuthenticationProcessor.handleClientAuthException`
  maps that to `Response.Status.UNAUTHORIZED`. Assertions 9 and 10 expect 401 on that
  basis, not on convention.

**Spring Security 6.5.5 / Spring Boot 3.5.5** (source at tags `6.5.5` and `v3.5.5`)

- `X509CertificateThumbprintValidator` exists in `spring-security-oauth2-jose`, is
  package-private, is wired by `JwtValidators.createDefault()`, and returns
  `success()` when `cnf` is absent.
- `Ssl.ClientAuth` has exactly `NONE`, `WANT`, `NEED`. `server.ssl.certificate`,
  `certificate-private-key`, `trust-certificate` and `client-auth` are the correct
  3.5.5 property names.
- The validator reads the certificate through `RequestContextHolder`, which is
  populated in time: `WebMvcAutoConfiguration` registers an
  `OrderedRequestContextFilter` at order **-105**, ahead of the
  `springSecurityFilterChain` registration at **-100**
  (`SecurityProperties.DEFAULT_FILTER_ORDER`). The validator runs in a filter, well
  before `DispatcherServlet`, so the ordering matters. This breaks under `@EnableWebMvc`
  and under WebFlux, neither of which is used here.
- Jakarta Servlet 6.0 section 3.11 fixes the attribute name
  `jakarta.servlet.request.X509Certificate`, an `X509Certificate[]` whose index 0 is
  the client leaf.

## Verified locally

Without bringing the stack up, since integration runs happen centrally:

- `certs/gen-certs.sh` runs clean. All four leaf certificates verify against the CA
  (`openssl verify`). Keys are PKCS#8. SANs cover both `localhost` and the compose
  service name.
- Client A's RFC 2253 subject is exactly `CN=mtls-client`, matching the realm export.
- The `x5t#S256` values agree across three independent computations: the openssl
  pipeline in `gen-certs.sh`, the pure-stdlib routine in `assertions.py`, and a
  direct check.
- A real TLS handshake against a throwaway `CERT_OPTIONAL` server using this PKI:
  both client certificates negotiate TLS 1.3, a no-certificate client is admitted at
  the transport, and the DER the server observes hashes to exactly the expected
  `cnf.x5t#S256`. This is the mechanism assertions 12 to 15 depend on.
- `docker compose config` parses.
- `assertions.py` compiles and its SSL contexts build with no deprecation warnings.

## Confirmed by execution

The full stack was brought up and `test/assertions.py` run against it: 24 assertions
passed, 0 failed (`results/assertions.txt`). The run confirmed what earlier drafts of this
file listed as unproven: Keycloak accepts the exact command line and imports the realm
preserving `clientAuthenticatorType: "client-x509"` and the client attributes; the
issuer-over-HTTPS with JWKS-over-HTTP split works; Tomcat surfaces the peer certificate
under `client-auth: want`; and the round-trip thumbprint Keycloak writes matches the one
Spring recomputes. C0 admits a replayed bearer token from any client, M1 accepts the token
only over the bound certificate and rejects it over a different certificate or none, and
the default validator admits an unbound token while a custom guard rejects it. Latency was
not measured and is not claimed.

## Reviewer-visible weaknesses

- **The central mechanism is a package-private class with no reference
  documentation.** Spring Security ships no public API and no docs page for RFC 8705
  on the resource server; the only documented proof-of-possession mechanism is DPoP.
  A future patch release could change the behaviour without a documented breaking
  change. The Spring Security version is pinned in `pom.xml` for this reason, and
  issue #17178 requests the class be made public, so the surface is acknowledged as
  unstable upstream.
- **The fail-open behaviour is load-bearing for the C0/M1 contrast and is a Spring
  choice, not an RFC 8705 requirement.** Assertions 5 and 7 are findings about Spring
  Security, not about the specification. They should not be reported as RFC
  conformance results.
- **`client-auth: want` weakens the deployment relative to production practice.** It
  is chosen for attributability, as argued above, but a reviewer may reasonably note
  that a real mTLS deployment would use `need` and that assertion 15 would then be
  satisfied at the transport instead. The paper should state the distinction.
- **The Keycloak discovery document is not evidence.** Keycloak hardcodes
  `tls_client_certificate_bound_access_tokens: true` in `OIDCWellKnownProvider`
  regardless of whether mTLS is configured. `assertions.py` prints it as INFO and
  never asserts on it. A reader who takes that field as configuration evidence would
  be misled.
- **Certificate B differs from A in both subject DN and key.** Assertions 9 and 14
  therefore do not isolate which difference caused each rejection. For assertion 14
  this is harmless, since the thumbprint covers the whole certificate, but a stricter
  design would add a third certificate sharing A's subject DN with a different key.
- **Single host, loopback, `start-dev`, no persistence.** Keycloak runs in dev mode
  with the in-memory database. This is adequate for correctness assertions and would
  not be adequate for anything with a latency number attached.
- **Only C0 and M1.** D2, D4, X1 and X2 are not covered here, and this directory
  makes no claim about proxy certificate propagation. `../../single-host-validation/`
  covers D1.

## Layout

```
certs/gen-certs.sh          disposable PKI, run before compose, output gitignored
docker-compose.yml          Keycloak 26.6.1 + resource server, HTTPS on 9443/9444
keycloak/realm-export.json  realm mtls-demo: bearer-client (C0), mtls-client (M1)
resource-server/            Spring Boot 3.5.5, Java 21, mTLS listener
test/assertions.py          the assertions above, PASS/FAIL per line
```

## Version pins

| Component | Version |
|-----------|---------|
| Keycloak | 26.6.1 |
| Spring Boot | 3.5.5 |
| Spring Security | 6.5.5 |
| Java | 21 |
