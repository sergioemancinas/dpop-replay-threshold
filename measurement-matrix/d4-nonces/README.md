# D4: DPoP with server-provided nonces

Condition D4 of `../../PROTOCOL.md` section 3. RFC 9449 sections 8, 8.2 and 9.

**Headline: Spring Security 6.5.5 has no DPoP nonce support of any kind.** Not partial, not
opt-in, not configuration-gated. There is no nonce claim validation, no `DPoP-Nonce` header,
no `use_dpop_nonce` error code, and no open issue or pull request requesting any of it.
Everything in this directory that concerns nonces was written here.

This directory is a feasibility investigation, not a latency measurement. It produces no
results files and no capacity numbers. Hypothesis H3 in `../../PREREGISTRATION.md` remains
untested.

## 1. What the library actually provides

Read at tag `6.5.5`, not inferred. The DPoP surface at that tag is ten files, found by
enumerating `git/trees/6.5.5?recursive=1` and filtering on `dpop`:

```
config/.../oauth2/server/resource/DPoPAuthenticationConfigurer.java
oauth2/oauth2-jose/.../oauth2/jwt/DPoPProofContext.java
oauth2/oauth2-jose/.../oauth2/jwt/DPoPProofJwtDecoderFactory.java
oauth2/oauth2-resource-server/.../authentication/DPoPAuthenticationProvider.java
oauth2/oauth2-resource-server/.../authentication/DPoPAuthenticationToken.java
docs/modules/ROOT/pages/servlet/oauth2/resource-server/dpop-tokens.adoc
(plus three test sources and one serialisation fixture)
```

A case-insensitive search for `nonce` across all of them returns nothing. Corroborating
evidence:

| Check | Result |
|-------|--------|
| `nonce` in any 6.5.5 DPoP source, test or doc | 0 hits |
| `DPoPProofJwtDecoderFactory` default validator chain (line 140-144) | `htm`, `htu`, `jti`, `iat` |
| `OAuth2ErrorCodes` DPoP entries (line 149) | `invalid_dpop_proof` only |
| `DPoPAuthenticationEntryPoint` response headers (line 217) | `WWW-Authenticate` only |
| GitHub code search, `repo:spring-projects/spring-security "use_dpop_nonce"` | 0 |
| GitHub code search, `repo:spring-projects/spring-security "DPoP-Nonce"` | 0 |
| Issues and PRs with `DPoP` in the title | 18, none about nonces |
| Same file on `main` (7.x) | still `htm`, `htu`, `jti`, `iat` |

Absent rather than merely unimplemented: there is no issue asking for it, so this is not a
tracked gap.

For completeness on the authorization-server side, Keycloak 26.6.1 is in the same position.
`keycloak/keycloak#39042`, "[DPoP] Implementing DPoP nonce", opened 2025-04-17, is still
open and unmilestoned, and `use_dpop_nonce` does not appear in the Keycloak source. D4 is
scoped to the resource-server nonce of RFC 9449 section 9, so this does not block the
condition, but it means neither end of the reference stack ships the mechanism.

## 2. Why the RFC's nonce is not the fix, and what is

This affects how the paper phrases the claim, and it cuts against the simple version of
the argument.

RFC 9449 section 11.1 is explicit that its nonces are **not** single-use:

> Server-provided nonces are an effective means for further reducing the chances for
> successful DPoP proof replay. Unlike cryptographic nonces, it is acceptable for clients to
> use the same nonce multiple times and for the server to accept the same nonce multiple
> times. As long as the jti value is tracked and duplicates are rejected for the lifetime of
> the nonce, there is no additional risk of token replay.

So an RFC-conformant nonce implementation does not remove the bounded-cache threshold. It
shrinks the window. Replay defence still rests on `jti` tracking; the nonce only bounds the
interval over which that tracking must hold, replacing the 60 s `iat` clock skew of
`JwtIssuedAtValidator` with the nonce lifetime. The threshold moves from `R* = N / W` to
`R* = N / W_nonce` and stays finite. A one-second nonce lifetime buys a 60x higher `R*` on
the shipped `N = 1000`, and nothing more.

The property that removes the threshold is **strict one-time use**, which RFC 9449 declines
to require. Under single use, a replayed proof presents a nonce the server has already
spent, so it is rejected at any request rate, with no dependence on cache occupancy. That is
the stronger property proposed by the formal analysis, and it is what is implemented here.

Two consequences for the paper:

- The gap is not only "Spring does not implement RFC 9449 section 8". It is that the fix
  from the formal analysis is **stricter than the RFC**, so an implementer cannot reach it
  by following the specification either. Conformance to section 8 is necessary and not
  sufficient.
- Single use relocates the unbounded state rather than eliminating it. The `jti` cache must
  hold one entry per request accepted inside the acceptance
  window, so its occupancy scales with **request rate**. The nonce store holds one entry per
  client key with a request in flight, so its occupancy scales with **client concurrency**.
  Overflow behaviour also inverts: `JtiCache` eviction fails open and admits a replay,
  whereas evicting an outstanding nonce fails closed and costs that client one extra round
  trip. `DPoPNonceStoreTests.overflowEvictsRatherThanGrows` asserts the latter.

## 3. What had to be written, and why each piece could not be avoided

The library offers exactly one public extension point in the proof path,
`DPoPProofJwtDecoderFactory.setJwtValidatorFactory`. It is not enough, for four independent
reasons, each verified against the 6.5.5 source.

**a. Replacing the validator chain discards the checks that bind the proof to the token.**
`setJwtValidatorFactory` replaces the chain wholesale. The public constant
`DEFAULT_JWT_VALIDATOR_FACTORY` restores only `htm`, `htu`, `jti` and `iat`. The `ath` and
`cnf.jkt` validators are `private static final` nested classes of
`DPoPAuthenticationProvider` (lines 144 and 189) and cannot be composed back in. Adding one
validator therefore forces an implementer to restate the two checks that actually bind the
proof to the access token. `RestatedDPoPValidators` does that, and
`NonceReplayTests.athMismatchIsStillRejected` and `jktMismatchIsStillRejected` guard against
dropping them silently.

**b. The provider discards the error, so RFC 9449 section 9 signalling is unreachable.**
`DPoPAuthenticationProvider` lines 119-121 catch every `JwtException` and substitute
`new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF)`, throwing away the `OAuth2Error` the
validators produced. A validator returning `use_dpop_nonce` would surface to the client as
`error="invalid_dpop_proof"`, which is the wrong error and which no conforming client will
retry on. The class is `public final` (line 61), so it cannot be subclassed. Hence
`NonceAwareDPoPAuthenticationProvider`, which is the library provider's logic plus error
preservation.

**c. No entry point can emit the header.** `DPoPAuthenticationEntryPoint` (configurer line
196) writes `WWW-Authenticate` and nothing else. It is a `private static final` nested class
of `DPoPAuthenticationConfigurer`, which is itself package-private, `final`, and exposes no
setters, and `OAuth2ResourceServerConfigurer.configure` applies it unconditionally whenever
`DPoPProofJwtDecoderFactory` is on the classpath. There is no DSL path to a different
failure handler. `DPoPNonceIssuingFilter` supplies `DPoP-Nonce` from outside the DPoP
machinery.

**d. Registering a competing provider is not sufficient.** `DPoPAuthenticationConfigurer`
line 83 registers its own `DPoPAuthenticationProvider` via `http.authenticationProvider`.
`ProviderManager` catches `AuthenticationException` and continues to the next supporting
provider, so a nonce rejection from a custom provider falls through to the library provider,
which does not check nonces, and the request is admitted. `NonceSecurityConfig` avoids this
by setting an explicit `AuthenticationManager`: `HttpSecurity.beforeConfigure` then
short-circuits and never builds the `AuthenticationManagerBuilder`, leaving the provider the
framework appends inert while the filters it creates still resolve the shared, and therefore
ours, `AuthenticationManager`.

### Provided versus added

| RFC 9449 requirement | Spring Security 6.5.5 | Added here |
|---|---|---|
| 4.3 (1-7) `typ`, `alg`, `jwk`, signature | `DPoPProofJwtDecoderFactory` | reused unchanged |
| 4.3 (8-9) `htm`, `htu` | `DEFAULT_JWT_VALIDATOR_FACTORY` | reused unchanged |
| 11.1 `jti` single use | `JtiClaimValidator`, `LinkedHashMap`, `MAX_SIZE = 1000` | reused unchanged, still bounded |
| 4.3 (11) creation-time window | `JwtIssuedAtValidator`, 60 s skew | reused unchanged |
| 4.3 (12) `ath` | private, not composable | `RestatedDPoPValidators.accessTokenHash` |
| 4.3 (12) `cnf.jkt` | private, not composable | `RestatedDPoPValidators.jwkThumbprint` |
| 4.3 (10) `nonce` claim match | **absent** | `NonceClaimValidator` |
| 8, 9 nonce issuance, unpredictable | **absent** | `DPoPNonceStore` |
| 8, 9 `DPoP-Nonce` response header | **absent** | `DPoPNonceIssuingFilter` |
| 8, 9 `use_dpop_nonce` error code | **absent** | `NonceClaimValidator`, `NonceAwareDPoPAuthenticationProvider` |
| 8.2 rotation on 200, `Cache-Control: no-store` | **absent** | `DPoPNonceIssuingFilter` |
| 11.3 no nonce-less proof once nonce supplied | **absent** | `NonceClaimValidator`, nonce always required |
| Strict single use (not an RFC requirement) | absent | `DPoPNonceStore.consume` |

444 non-comment lines of Java across eleven files. 376 of those sit in the authentication
path, excluding the application shell, the control config and the properties holder. The
security-critical core, meaning the store, the three validators, the provider and the
thumbprint helper they share, is 267 lines. This is the cost being documented. It is not a
library capability, and the paper should not describe it as one.

## 4. What was executed

`mvn test` under `resource-server/`. 14 tests, all passing, in process, no Docker, no
Keycloak. The access token is minted and decoded locally because these tests exercise proof
validation, not token issuance.

The headline test is `NonceReplayTests.replayIsRejectedAfterTheProbeJtiHasBeenEvicted`. It
drives the real `DPoPProofJwtDecoderFactory` chain and the real static `JtiCache` to genuine
eviction, then replays the probe:

1. Challenge, no nonce, take the supplied nonce.
2. Probe proof with `jti = J` and that nonce. Accepted.
3. Witness proof with `jti = C`, inserted immediately after the probe.
4. 1024 unique-`jti` requests, each spending the nonce returned by the previous response.
   `JtiCache.removeEldestEntry` returns true at `size() > 1000`, so this displaces both.
5. Re-present `jti = C`. Accepted, which proves `C` was evicted, and therefore that `J`,
   inserted earlier under an insertion-ordered evict-eldest policy, was evicted too.
6. Replay the probe verbatim, same `jti`, same `iat`, same nonce. **401,
   `WWW-Authenticate: DPoP error="use_dpop_nonce"`**, with a fresh `DPoP-Nonce` so the client
   can recover.

Step 5 is not decoration. `DelegatingOAuth2TokenValidator` accumulates the errors of every
validator instead of short-circuiting, so observing `use_dpop_nonce` on the response would
not on its own show that the `jti` check passed. Without the witness the rejection would be
unattributable.

`BaselineReplayControlTests` runs the same procedure against `BaselineSecurityConfig`, which
is Spring Security defaults and is substantively the D1 resource server. Its replay returns
**200**. That is the control: it confirms eviction really occurs on this code path, so the
D4 rejection is attributable to the nonce and not to a cache that still holds the `jti`.

Both tests assert that the replay lands within 45 s of the probe, since a replay outside the
60 s `iat` window would be rejected for the wrong reason.

The remaining tests cover single use with a fresh `jti`, the section 9 challenge shape,
at most one `DPoP-Nonce` header, `Cache-Control: no-store`, key binding, `ath` and `cnf.jkt`,
and the store's expiry and overflow behaviour.

Eviction is driven by insertion count rather than by sustained rate. Under the evict-eldest
policy the two are equivalent for this outcome, and count is deterministic, so the test does
not depend on scheduler timing the way the D1 rate sweep does.

## 5. Execution status

`docker-compose.yml` brings up Keycloak 26.6.1 and this resource server on host ports
**8090** (Keycloak HTTP), **9010** (Keycloak management) and **8091** (resource server),
disjoint from the 8080, 8081 and 9000 used by `../../single-host-validation/`. It was
validated with `docker compose config` and has since been brought up. The realm is
mounted from the D1 stack rather than copied, because D4 changes only the resource server.

`client/nonce_client.py` is a challenge, retry and replay smoke check against that stack. It
has been run; see `results/nonce-flow.txt`. It imports the D1 driver's key handling rather than duplicating it, and
adds only the nonce claim, which that driver does not carry.

No latency was measured. H3 predicts D4 reduces p99 variance against D2 by at least 20%;
D2 does not exist in this repository and no p99 was captured here.

## 6. Threats to validity

- The tests use MockMvc, not a network path. That is appropriate for a binary
  admitted-or-rejected outcome and inappropriate for anything about latency, which is why
  no latency is claimed.
- The access token is locally minted. Keycloak's issuance path is exercised in D1 and is not
  re-exercised here.
- The nonce is issued against a thumbprint read from an unverified proof header. This is
  deliberate. The binding decides who may later spend the nonce, and only the holder of the
  private key can produce a proof that survives signature verification, so an attacker can
  mint nonces against a victim's public thumbprint but cannot spend them. The residual
  exposure is store occupancy, bounded by `d4.nonce.max-outstanding` and the TTL.
- Issuing a nonce on every DPoP request, including ones that go on to fail, is the section
  8.2 efficient case and keeps the challenge and rotation paths identical. It also means an
  unauthenticated caller can consume store slots up to the bound.
- The nonce store is process-local. Behind more than one replica a client would receive a
  nonce from one node and present it to another. Making D4 work across replicas needs the
  same shared-state machinery as D2, which is unbuilt. This is the same limitation the
  Spring maintainer describes for the `jti` cache in `spring-projects/spring-security#18120`.
- Tests were compiled and run with `--release 21` on a JDK 25 toolchain, the only JDK
  available on the build host. The Docker image pins `eclipse-temurin:21`.

## Version pins

Keycloak 26.6.1, Spring Boot 3.5.5, Spring Security 6.5.5, Java 21.

## Layout

```
docker-compose.yml            executed, see results/nonce-flow.txt
client/nonce_client.py        executed against the live stack
resource-server/
  src/main/java/.../
    DPoPNonceStore.java                        nonce issuance and single-use consumption
    NonceClaimValidator.java                   RFC 9449 4.3 step 10, use_dpop_nonce
    RestatedDPoPValidators.java                ath and cnf.jkt, restated because private
    NonceAwareDPoPAuthenticationProvider.java  provider, restated because final
    DPoPNonceIssuingFilter.java                DPoP-Nonce response header
    DPoPProofKeys.java                         RFC 7638 thumbprints
    NonceSecurityConfig.java                   D4 wiring
    BaselineSecurityConfig.java                library defaults, the control
  src/test/java/.../                           14 tests, executed
```
