# Measurement Protocol

Mirrors the methodology section of the accompanying paper. Sections marked NOT EXECUTED
describe planned work; no results exist for them.

## 1. Hardware

**Single-host validation (executed).** One machine. One authorization server, one
resource-server node, one co-located load generator. Loopback is acceptable here because
the threshold under test concerns cache eviction behaviour, not network latency.

**Distributed comparison (NOT EXECUTED).** Two hosts over a local network, one running the
resource-server topology and one generating load, so traffic crosses a real network path.
A cloud virtual-machine pair provides cross-environment ratio validation. Commodity
hardware under exclusive, non-shared control, following Maricq et al., because the
comparison subordinates absolute capacity to relative differences between conditions.

## 2. Stack

| Role | Component |
|------|-----------|
| Authorization server | Keycloak 26.6.1, DPoP-enabled realm exporting `cnf.jkt`, ES256 |
| Resource server | Spring Boot 3.5.x, Spring Security 6.5.x, `DPoPProofJwtDecoderFactory` |
| Replay cache (single-node) | Spring default `LinkedHashMap`-backed cache, `N = 1000` |
| Replay cache (distributed, NOT EXECUTED) | Redis 7.x, `SET key value NX EX ttl` |
| mTLS (NOT EXECUTED) | self-signed client certs, `tls_client_auth`, NGINX termination with explicit XFCC propagation |
| Persistent state | PostgreSQL 16 (dev-mode H2 in the single-host demo) |
| Observability (NOT EXECUTED) | Prometheus, Grafana, cAdvisor |

The single-host demonstration deliberately omits Redis, NGINX and the replica set. Adding
them would change the cache under test and invalidate the threshold being measured.

## 3. Conditions

C0 bearer baseline; D1 DPoP single-node default cache; D2 DPoP three-replica Redis;
D4 DPoP server-provided nonces; M1 mTLS certificate-bound tokens; X1 correct XFCC
propagation; X2 broken XFCC URL-encoding.

**Executed here: D1 only.**

## 4. Single-host validation procedure (executed)

The analytical model predicts a sharp binary outcome: replay is admitted if and only if
`R > R*`. The procedure tests exactly that.

1. Obtain a DPoP-bound access token from Keycloak. Confirm the token carries a `cnf.jkt`
   thumbprint matching the client key.
2. Confirm baseline replay defence: send one proof twice at idle. The second must be
   rejected.
3. For each rate `R` in the sweep set, spanning `R*` from below to above:
   a. Drive unique-`jti` proofs at sustained rate `R` for a duration exceeding `W = 60 s`,
      so that the cache reaches steady state.
   b. Issue a probe proof, hold it, continue the unique-`jti` load, then replay the probe
      inside its `iat` window.
   c. Record whether the replay was accepted (HTTP 200) or rejected (HTTP 401).
4. Expected outcome: rejection below `R*`, acceptance above `R*`, with the transition at
   `R* ~= 17` req/s.

Each rate is repeated to distinguish a genuine threshold crossing from a single scheduling
artefact. Rates, repetitions and the observed transition point are recorded in
`single-host-validation/results/`.

## 5. Load generation and statistical pipeline (NOT EXECUTED)

For the distributed comparison: load generated with `wrk2` and `k6` with HdrHistogram
capture. Per-condition replication determined by CONFIRM-style pilot analysis targeting a
bootstrap BCa 95% confidence interval width of <= +/- 5% of median p99. Stationarity by
Kolmogorov-Smirnov on split halves. Kruskal-Wallis omnibus, Dunn post-hoc with Holm
correction. Effect sizes as Cliff's delta with Romano-Kromrey thresholds.
Coordinated-omission correction client-side per wrk2, with server-side omission disclosed
as a threat to validity.

The single-host validation does not use this pipeline. Its outcome is binary
(replay admitted or not), so it needs no distributional statistics.

## 6. Correctness suite

See `PREREGISTRATION.md`. Tests requiring Redis or multiple replicas are skipped in the
single-host demonstration and reported as skipped, not as passed.
