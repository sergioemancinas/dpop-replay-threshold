# Conditions X1 and X2: certificate binding across a TLS-terminating proxy

Class B2 of the taxonomy is *TLS termination with lossy metadata propagation*: mTLS
terminates at a proxy, and the proxy either fails to propagate client certificate
metadata to the application or propagates it in a form the application cannot parse. The
real-world instance is CVE-2024-10039 in Keycloak.

This directory holds the stack, the test harness, the argument, and the results of
running it. All 25 assertions passed against the live stack; see
`results/xfcc-outcomes.txt`.

## The one-sentence version

RFC 8705 section 6.5 says how client certificate metadata reaches the application behind
a terminating proxy is out of scope. Everything in this directory is the cost of that
sentence.

## Why Envoy and not NGINX

`X-Forwarded-Client-Cert` is Envoy's header. Envoy defines it, Envoy's HTTP connection
manager emits it, and the field grammar is Envoy's:

| Field | Content | Source |
|---|---|---|
| `By` | URI SAN of the proxy's own certificate | `conn_manager_utility.cc` |
| `Hash` | `Hex::encode(SHA256(DER))` of the peer certificate | `connection_info_impl_base.cc` |
| `Cert` | peer certificate, PEM, percent-encoded, double-quoted | same |
| `Chain` | peer chain, PEM, percent-encoded, double-quoted | same |
| `Subject` | subject DN, always double-quoted | `conn_manager_utility.cc` |
| `URI`, `DNS` | SANs of the peer certificate | same |

NGINX has no XFCC. It exposes `$ssl_client_cert`, which nginx's own documentation
deprecates and which prepends a tab to every line but the first; `$ssl_client_escaped_cert`,
urlencoded PEM; and `$ssl_client_fingerprint`, which nginx documents as the **SHA-1**
fingerprint and which is therefore useless for RFC 8705. A faithful NGINX equivalent is:

```nginx
proxy_set_header X-Forwarded-Client-Cert "Cert=\"$ssl_client_escaped_cert\"";
```

That is a reconstruction of Envoy's convention in NGINX, not the convention itself, and
the reconstruction is where a second family of encoding mismatches lives. Since the
condition is named after Envoy's header, the stack uses Envoy. The NGINX line is here so
a reader can see the shape of the alternative, and it is not exercised.

## What the resource server has to do, and why it needs custom code

Spring Security 6.5.5 ships the RFC 8705 section 3.1 check. It is
`org.springframework.security.oauth2.jwt.X509CertificateThumbprintValidator`, and it is
wired into every decoder built through `JwtValidators.createDefault`,
`createDefaultWithIssuer` or `createDefaultWithValidators`. Spring Boot's
`OAuth2ResourceServerJwtConfiguration.JwtDecoderConfiguration` uses those factories, so
an ordinary Boot resource server with `issuer-uri` and `jwk-set-uri` set is **already**
validating `cnf.x5t#S256`, whether or not the developer knows it.

Three properties of that validator decide everything that follows. All three were read
from the 6.5.5 tag, not assumed:

1. **It obtains the certificate from the servlet TLS contract.** Its
   `DefaultX509CertificateSupplier` reads the request attribute
   `jakarta.servlet.request.X509Certificate`. Tomcat populates that from its own TLS
   layer. Behind a terminating proxy there is no TLS layer under Tomcat, so the
   attribute is absent and something in application code has to put it back. RFC 8705
   declines to say what.

2. **It fails closed.** If `cnf.x5t#S256` is present and no certificate is available it
   returns `invalid_token` with the description "Unable to obtain X509Certificate from
   current request." This finding cuts against the naive form of the claim: **in Spring
   Security, losing the certificate metadata produces a 401, not a silent acceptance.**

3. **It returns success when the claim is absent.** A token with no `cnf.x5t#S256` is not
   its business. That is correct per RFC 8705, and it is the quietest failure in the
   class: if the authorization server never managed to bind the token in the first
   place, nothing downstream ever says so.

Because the validator is package-private and its `Supplier<X509Certificate>` constructor
is not reachable from application code, the only way to feed it a proxy-propagated
certificate is to restore the servlet attribute it already reads. That is
`XfccClientCertificateFilter`, and it is the irreducible custom code the condition is
about.

## The design

Two axes, crossed, one variable each.

**Propagation** (Envoy, `envoy/envoy.yaml`, two listeners):

- Listener A, host port `18443`: `set_current_client_cert_details` with
  `cert`, `chain`, `subject`, `uri`, `dns`. Complete.
- Listener B, host port `18444`: `subject`, `uri`, `dns` only. The header arrives, the
  certificate does not. This is limb one of B2 and it is a plausible misconfiguration
  rather than an exotic one, because Subject and DNS are what most deployments actually
  consume and `cert` defaults to false.

**Application** (four containers, identical image, two environment variables):

- `XFCC_URL_DECODE=true` (X1) or `false` (X2). Envoy percent-encodes the PEM. X2 parses
  it without decoding. This is limb two of B2.
- `XFCC_BINDING_POLICY=strict` or `lenient`. `strict` leaves Spring Boot to
  autoconfigure the decoder, so Spring Security's own fail-closed validator runs.
  `lenient` supplies a `JwtDecoder` bean, which makes
  `@ConditionalOnMissingBean(JwtDecoder.class)` back the autoconfiguration off entirely,
  and installs `LenientCertificateBindingValidator`: byte-for-byte the shipped logic with
  one branch changed, "no certificate available" returning success instead of failure.

Envoy routes to the four containers by path prefix, so both listeners reach all four
cells.

### Predicted outcomes

Both clients are signed by the same CA, so both complete the TLS handshake. Any rejection
of `client-bad` is the binding check, not TLS.

| Cell | propagation | decode | policy | `client-good` | `client-bad` |
|---|---|---|---|---|---|
| X1 strict | complete | yes | strict | 200 | 401 |
| X1 lenient | complete | yes | lenient | 200 | 401 |
| X2 strict | complete | no | strict | 401 | 401 |
| X2 lenient | complete | no | lenient | 200 | **200** |
| B strict | lossy | n/a | strict | 401 | 401 |
| B lenient | lossy | n/a | lenient | 200 | **200** |

The two bold cells are the silent binding failure: a token that advertises itself as
sender-constrained, presented over mTLS with the wrong certificate, accepted with HTTP
200 and no error anywhere on the response path.

`X1 lenient` is the control that makes the result mean something. The lenient policy
enforces the binding correctly when propagation works. So the acceptance in `X2 lenient`
is attributable to the propagation defect, not to the policy being broken on its own.

`X2 strict` is the honest counterweight. The encoding mismatch alone, against stock
Spring Security, is an availability failure: everything is rejected. The cause is
invisible, appearing only as a DEBUG-level log line inside the shim, but the request does
not get through. **The encoding mismatch does not by itself produce a silent
acceptance.** Silence needs the lenient shim as well.

That combination is not a strawman. A shim that fails closed rejects every request that
legitimately arrives without a client certificate, including health checks and any
non-mTLS ingress path, and the fastest way to make that outage stop is to stop failing.
The lenient branch is the predictable end state of a fail-closed shim meeting an
operational incident. But it is a claim about engineering practice, not something this
demonstration measures, and it should be read as such.

## What this proves

- RFC 8705 section 3.1 semantics are implemented correctly and identically in three
  places: `pki/generate_pki.py`, `LenientCertificateBindingValidator.thumbprint`, and
  Spring Security's own `X509CertificateThumbprintValidator.computeSHA256Thumbprint`.
  All three compute base64url(SHA-256(DER)) without padding. Verified against
  `openssl x509 -fingerprint -sha256` as an independent oracle.
- Envoy's `Hash` field carries the same digest in lowercase hex. An application that
  compares `Hash` directly to `cnf.x5t#S256` never matches, even with the right
  certificate. Verified.
- A percent-encoded XFCC `Cert` value cannot be parsed by
  `CertificateFactory.getInstance("X.509")`; it throws
  `CertificateException: ... Illegal header: -----BEGIN%20CERTIFICATE-----`. Verified.
- With the correct decode, the same value parses and yields the expected thumbprint.
  Verified.
- The four-cell divergence. **Run. 25 assertions passed; see `results/xfcc-outcomes.txt`.**

## What this does not prove

- **Nothing here is a defect in Spring Security.** The shipped validator fails closed.
  `LenientCertificateBindingValidator` is application code written for this
  demonstration, and the README says so because a reader skimming the matrix could
  otherwise conclude the framework is unsafe. It is not.
- **Nothing here is a reproduction of CVE-2024-10039.** That CVE is Keycloak trusting
  client certificate metadata that reached it through a non-pass-through proxy. This
  stack is a resource server, not Keycloak, and Envoy is configured with
  `forward_client_cert_details: SANITIZE_SET`, which discards any client-supplied XFCC
  before setting its own. The harness asserts that a forged header is ignored. The CVE is
  the motivating example for the failure class; it is not the thing under test.
- **No frequency claim.** Four synthetic cells say nothing about how often real
  deployments land in them. The paper must not cite this as prevalence evidence.
- **No latency or capacity claim.** Nothing here is a benchmark.
- **Nothing about multi-hop XFCC.** With more than one proxy the header carries several
  elements and the application needs a policy about which to trust. `XfccHeader` takes
  the first. That is a defensible default for a single terminating proxy and an
  unexamined one for anything else.
- **Nothing about `Chain`.** The shim reads `Cert` only. A deployment that needs to
  validate the chain at the application has a larger problem than this condition covers.

## Why there is no Keycloak in this stack

The repository pins Keycloak 26.6.1 and uses it in `../../single-host-validation/` and in
`../baseline-and-mtls/`, which is condition M1 and which does stand up Keycloak with
`--https-client-auth` and a lab CA truststore. Issuance of certificate-bound tokens is
M1's job. It is deliberately absent here, for three reasons.

1. **Separation of variables.** The variable under test is proxy-to-application
   propagation and the resource server's confirmation check. Keycloak's role would be
   minting `cnf.x5t#S256`, which is upstream of that variable. Include it and a failing
   cell could be Keycloak's issuance or the resource server's validation, and the harness
   could not tell them apart. M1 owns issuance; X1 and X2 own propagation.
2. **Keycloak cannot mint certificate-bound tokens through a TLS-terminating proxy.**
   That is precisely CVE-2024-10039, and the remedy was to require pass-through TLS. A
   Keycloak in this stack would need its own direct-mTLS path bypassing Envoy, which is a
   second network topology in service of a step this experiment does not measure. Note
   that M1's compose reaches Keycloak directly for exactly this reason.
3. **Keycloak's binding under non-certificate grants has open upstream discussions**
   (keycloak discussion #13482 on the direct grant, #36802 on non-certificate
   authentication). Depending on it would make this condition fragile for reasons
   unrelated to the claim. Those threads were read, not reproduced.

Tokens are therefore minted by `test/tokens.py` with an ES256 key whose public half is
published as a static JWKS by an nginx container. The resource server validates issuer,
signature and expiry exactly as it would against Keycloak. Substituting a real
authorization server changes nothing in the six cells, and is the natural extension if
the condition is ever promoted from demonstration to measurement.

## Layout

```
docker-compose.yml        four resource servers, one Envoy, one static JWKS host
envoy/envoy.yaml          two listeners differing only in set_current_client_cert_details
pki/generate_pki.py       CA, server cert, two client certs, token signing key, JWKS
resource-server/          Spring Boot 3.5.5, Spring Security 6.5.5 pinned explicitly
  .../XfccHeader.java                        header grammar and percent-decoding
  .../XfccClientCertificateFilter.java        the propagation shim
  .../LenientCertificateBindingValidator.java the one-branch mutation
  .../XfccResourceServerApplication.java      wiring for the four cells
  src/test/java/.../XfccHeaderTests.java      7 self-contained unit tests
test/tokens.py            token minting and Envoy encoding primitives
test/test_xfcc.py         PASS/FAIL harness
```

## Running

```
python3 pki/generate_pki.py

# Invariants that need no containers. These are the assertions actually verified.
python3 test/test_xfcc.py --local

# Full run against the live stack (25 assertions, see results/xfcc-outcomes.txt).
docker compose up -d --build
python3 test/test_xfcc.py
docker compose down -v
```

Requires `python3` with `httpx` and `cryptography`, and `openssl` on `PATH` for the
independent digest oracle. Host ports used: `18080`, `18443`, `18444`. The ports
`8080`, `8081` and `9000` belong to `../../single-host-validation/` and are untouched.

Assertions are made on HTTP status codes only. The response body carries diagnostics and
is printed, never asserted on, so a defect in the diagnostics cannot turn a failing
assertion into a passing one.

## Status

Executed and passing on the machine this was written on:

- `pki/generate_pki.py`, and its thumbprints cross-checked against `openssl`.
- `test/test_xfcc.py --local`, 9 assertions.
- `mvn test` in `resource-server/`, 7 assertions, against Spring Security 6.5.5
  resolved from Maven Central. Compiled with `release 21` under a JDK 25 toolchain,
  because no JDK 21 was available locally; the Docker build uses
  `maven:3.9-eclipse-temurin-21`.
- `docker compose config`.
- `envoy --mode validate` against `envoy/envoy.yaml` on `envoyproxy/envoy:v1.35.13`,
  with the PKI mounted: 4 clusters, 2 listeners, `configuration OK`.

Executed:

- `docker compose up` was run against a shared host, and every row of the outcome table
  above was confirmed against the live stack;
  see `results/xfcc-outcomes.txt`.

Assumptions a run would settle, listed because they are the likely failure points:

- That Tomcat honours an explicitly set `jakarta.servlet.request.X509Certificate`
  request attribute over a plain HTTP connector. `Request.getAttribute` consults its own
  attribute map before delegating, so it should, but this has not been observed.
- That `OrderedRequestContextFilter` at `REQUEST_WRAPPER_FILTER_MAX_ORDER - 105` runs
  before the security chain at `REQUEST_WRAPPER_FILTER_MAX_ORDER - 100`, so that
  `RequestContextHolder` is populated when the validator runs. The constants were read
  from Spring Boot 3.5.5; the resulting behaviour has not been observed.
- That the percent-encoded `Cert` plus `Chain` fits the request header limit.
  `server.max-http-request-header-size: 32KB` is set in `application.yml` because
  Tomcat's 8 KB default is comfortable for the P-256 certificates generated here and is
  not for RSA-4096. Set defensively, not because it was observed to be needed.
- That the two environment variables in `docker-compose.yml` bind. They copy the names
  used by `../../single-host-validation/`, which is the only evidence in this repository
  that Boot's relaxed environment binding accepts that spelling for a hyphenated
  property. Everything without that precedent is in `application.yml`.

## What a reviewer could reasonably challenge

1. **The lenient validator is ours.** The silent cells depend on a branch this repository
   wrote. The counter is `X2 strict`, which shows what unmodified Spring Security does,
   and the explicit statement above that the framework fails closed. A reviewer who
   thinks the lenient branch is unrepresentative is challenging a claim about engineering
   practice, and that claim is not measured here.
2. **The encoding mismatch is application-side.** Envoy cannot be configured to emit a
   raw, undecoded PEM; `urlEncodedPemEncodedPeerCertificate` is the only form. So X1 and
   X2 put identical bytes on the wire and differ in the parser. A mismatch is a relation
   between two ends and either end can be the wrong one, but a reviewer expecting a
   misconfigured proxy will not find one. Listener B is the genuine proxy-side defect,
   and it is limb one rather than an encoding mismatch.
3. **The issuer is a stub.** Defended above, but it is a substitution and a reviewer may
   want Keycloak in the loop.
4. **Two clients, one CA, no revocation, no chain validation at the application.** The
   design isolates the binding check. A reviewer interested in PKI
   failure modes will find none of them here.
5. **The lenient cells rest on a branch this repo wrote.** The silent-accept outcome is
   demonstrated with a deliberately lenient validator, labelled as such; stock Spring
   fails closed on missing metadata, which the strict cells show.
6. **Four cells are not a sample.** Nothing here supports a claim about how common any
   of this is.

## Sources read

- RFC 8705 sections 3, 3.1 and 6.5. Section 3.1 defines `x5t#S256` as the
  base64url-encoded SHA-256 hash of the DER encoding of the certificate. Section 3
  requires the protected resource to obtain the certificate "from its TLS implementation
  layer". Section 6.5 places propagation from an intermediary out of scope.
- Spring Security 6.5.5: `X509CertificateThumbprintValidator`, `JwtValidators`,
  `NimbusJwtDecoder`.
- Spring Boot 3.5.5: `OAuth2ResourceServerJwtConfiguration`, `WebMvcAutoConfiguration`,
  `OrderedRequestContextFilter`, `SecurityProperties`.
- Envoy 1.35.13: `source/common/http/conn_manager_utility.cc`
  (`mutateXfccRequestHeader`), `source/common/tls/connection_info_impl_base.cc`,
  `source/common/http/utility.{h,cc}` (`PercentEncoding::urlEncode`).
- GHSA-93ww-43rr-79v3 / CVE-2024-10039, and keycloak#35217.
