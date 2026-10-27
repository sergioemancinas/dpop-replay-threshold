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

## Results

Not yet run.
