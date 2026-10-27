# Follow-up: Spring Security 7.1.2

Spring Security 7.0.7 and 7.1.1 (2026-08-20) replaced the bounded `JtiCache` studied in
the paper with `DPoPProofReplayValidator`. This directory runs the single-host stack
again with the resource server on Spring Security 7.1.2 (Spring Boot 4.1.2). Keycloak,
the realm, the client code and the endpoint are unchanged.

## What changed, read from the 7.1.2 source

- `DPoPProofJwtDecoderFactory` checks `htm`, `htu`, `iat`, `jkt`, `ath` and only then
  the replay validator, and the chain stops at the first error (`setFailOnError(true)`).
  A proof that fails the key binding is never stored.
- `iat` must be within ±30 s (was ±60 s). A stored entry expires at `iat + 30 s`.
- `InMemoryCache`: at most 100,000 entries in total and at most 1000 per client key
  (JWK thumbprint). When either limit is reached, the proof is rejected; nothing is
  evicted. Expired entries are removed by a cleanup that runs at most every 10 s,
  triggered by inserts.

## Predictions

Written before any run; the commit that adds this file precedes the results commit.

With honest traffic an entry stays stored for `T` between about 29 s (expiry) and 40 s
(expiry plus the cleanup interval). One client key can therefore hold its 1000-entry
quota only while `R × T ≤ 1000`.

| Exp. | Setup | Prediction |
|---|---|---|
| A | probe, unique-jti load at R = 5, 17, 18, 25, 40 req/s, replay at t = 28 s | replay rejected at every rate. At 40 req/s, load requests start failing near t = 1000/40 = 25 s (per-key limit), none at 25 req/s or below |
| B | 1050 proofs under the attacker's own key with the victim's token, then replay the captured victim proof | every flood request 401; replay 401 before and after the flood |
| C | one client key at R = 15…50 req/s for 70 s | R ≤ 25: no rejections. 25 < R ≤ 33: intermittent rejections, following the 10 s cleanup cycle. R > 33: sustained rejections from about t = 1000/R s, accepted rate in the last 30 s between 25 and 34.5 req/s |

In short: the fix should close the replay of Sec. V and the attacker flood of Fig. 2,
and replace them with a loud per-client-key limit near 25–33 req/s per node. The
node-wide 100,000-entry limit implies a second limit near 2,500–3,450 req/s in
aggregate, which this load generator cannot reach and which is not tested here.

## Running

Needs Docker (colima works) and `python3` with `httpx` and `cryptography`.

```
docker compose up -d --build
python3 probe.py all      # about 25 min; writes results/A.json, B.json, C.json
docker compose down -v
```

## Deviation: DPoP is opt-in in 7.x

The first run (2026-10-27) rejected every request, including the first use of a fresh
proof, with `WWW-Authenticate: Bearer`. In 7.1.2, `OAuth2ResourceServerConfigurer`
installs DPoP only when `.dPoP(...)` is called; 6.5 installed it whenever
`DPoPProofJwtDecoderFactory` was on the classpath. The resource server now calls
`.dPoP(Customizer.withDefaults())`, the only change to the code that was committed with
the predictions, and that run's output was discarded.

Checked on the server without `.dPoP(...)`: a DPoP-bound access token sent as a plain
`Bearer` token, without a proof, is rejected with 401 `invalid_token`. An application
upgraded from 6.5 to 7.x without adding `.dPoP(...)` therefore fails loudly; it does
not silently accept DPoP-bound tokens as bearer tokens.

## Results

Run on 2026-10-27, one machine (colima, 6 CPUs), outputs in `results/`.

| Exp. | Observed | Prediction |
|---|---|---|
| A | replay rejected (401) at 5, 17, 18, 25 and 40 req/s. Load fully accepted up to 25 req/s; at 40 req/s, 999 load requests accepted (plus the probe: 1000) and 121 rejected from t = 25 s | held |
| B | victim proof 200 on first use; 401 before the flood, 1050 × 401 during it, 401 after it | held |
| C | see below | held |

Experiment C, one client key for 70 s:

| R (req/s) | accepted | rejected | first rejection | accepted, last 30 s |
|---:|---:|---:|---:|---:|
| 15 | 1050 | 0 | – | 15.0 |
| 20 | 1400 | 0 | – | 20.0 |
| 24 | 1680 | 0 | – | 24.0 |
| 26 | 1802 | 18 | 39.4 s | 25.9 |
| 28 | 1860 | 100 | 36.5 s | 27.9 |
| 30 | 1920 | 180 | 34.1 s | 29.9 |
| 32 | 1976 | 264 | 31.8 s | 31.9 |
| 35 | 2015 | 435 | 28.6 s | 33.3 |
| 40 | 2015 | 785 | 25.0 s | 33.3 |
| 50 | 2012 | 1488 | 20.0 s | 33.3 |

- The first rejection comes at `t ≈ 1000/R` at every rate above 25 req/s (38.5, 35.7,
  33.3, 31.3, 28.6, 25.0, 20.0 s predicted), when the key's 1000-entry quota fills before
  its first entries expire.
- Between 26 and 32 req/s the rejections fall almost entirely in that first fill (30–40 s
  bucket); afterwards the client is accepted at its full rate with at most a few
  rejections per 10 s.
- Above 33 req/s the client is capped at exactly 1000 / 30 s = 33.3 accepted req/s and
  every further request is rejected with 401 `invalid_dpop_proof`. In steady state an entry
  stayed for 30 s, the lower end of the predicted 29–40 s.

## What this means

On Spring Security 7.1.2 the replay of Sec. V and the attacker flood of Fig. 2 are closed.
The limit has not disappeared, it has changed sides: one client key is now capped at
`maxRequestsPerKey / clockSkew` = 1000 / 30 s ≈ 33 accepted requests per second per node,
and a client above about 25 req/s is rejected for a while every time it starts. The failure
is loud (401) instead of silent (replay accepted), which is the trade the CVE fix intends.
The per-key limit is documented in the API; the resulting rate ceiling is not.

Not tested: the node-wide 100,000-entry limit, several nodes, a distributed `Cache`
implementation.
