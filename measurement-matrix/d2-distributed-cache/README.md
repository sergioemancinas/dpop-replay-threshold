# D2: Distributed Replay Cache

**Status: executed. Default cache 11 passed, Redis shared cache 12 passed including the fail-closed check. See `results/`.** No latency was measured.

Two binary correctness facts about DPoP proof replay across resource-server replicas. No
latency is measured and none is claimed.

| | Cache | Replay to a *different* replica |
|---|---|---|
| Fact 1 | Spring Security default, process-local | **admitted**, at any rate |
| Fact 2 | Redis-backed, shared by all replicas | **rejected** |

## Fact 1: the multi-node hole

`DPoPProofJwtDecoderFactory` installs a default validator chain of `htm`, `htu`,
`JtiClaimValidator`, `JwtIssuedAtValidator`. `JtiClaimValidator` is a private inner class
holding a `static LinkedHashMap` (`Collections.synchronizedMap`), bounded at
`MAX_SIZE = 1000`. Static means per JVM. Three replicas therefore have three disjoint
replay caches and no shared state whatsoever.

This is a different failure from D1. D1 needs sustained load above `R* = N / S ~= 17` req/s,
where `S` is the 60 s clock-skew tolerance, to evict the entry before the proof's `iat`
window closes. D2 needs no load at all: the
second presentation simply lands on a process that has never seen the `jti`. The test paces
presentations one second apart, roughly `1/17` of `R*`, so eviction cannot be the
explanation.

Reported as spring-projects/spring-security#18120, *"DPoP JtiClaimValidator does not prevent
replay attack on multi-node setup"*, closed as a duplicate. RFC 9449 Sec. 11.1 anticipates
it: "multiple servers behind a single endpoint have no shared state".

## Fact 2: the shared cache

`RedisJtiClaimValidator` claims the identifier with a single
`SET dpop:jti:<sha256(jti)> <node> EX 125 NX`. One round trip both tests and claims, so two
replicas racing the same proof cannot both win. The `jti` is hashed before it becomes a key,
matching what the library does with its own map.

**TTL.** `JwtIssuedAtValidator` accepts `iat` within +/- 60 s of now. A proof first seen at
`t0` carrying `iat = t0 + 60` stays `iat`-valid until `t0 + 120`, so 120 s is the tight lower
bound on the entry's lifetime with synchronised clocks. Shorter and a proof could outlive its
own cache entry. Each replica checks `iat` against its own clock while Redis expires the key on
its clock, so a replica running `d` seconds behind Redis keeps accepting the proof `d` seconds
after the entry is gone. The TTL is therefore 125 s, a 5 s margin for clock offset. The
committed results were recorded with 120 s; their outcomes do not depend on the TTL, because
every replay in them happens within seconds of first use.

**Ordering.** The shared entry is written only after the library has validated the proof and
its binding (`htm`, `htu`, `iat`, `ath`, `jkt`), so a request that fails those checks never
consumes a shared entry.

**Limit.** One Redis instance, no replica. With Redis replication, an acknowledged `SET NX`
can be lost on failover, which would let a proof be accepted twice; that case is not tested
here.

**Fail closed.** Any exception reaching the validator, connection refused or timeout,
produces `invalid_dpop_proof`. Single use is the entire replay defence; with the shared cache
unreachable it cannot be enforced, and admitting the proof would silently reinstate fact 1.

## How the shared cache is installed

Spring Security 6.5.5 offers exactly one public seam,
`DPoPProofJwtDecoderFactory.setJwtValidatorFactory(Function<DPoPProofContext, OAuth2TokenValidator<Jwt>>)`,
and it replaces the whole chain rather than extending it. There is no supported way to get a
customised factory into the resource-server filter chain:
`DPoPAuthenticationConfigurer` is package private and does
`http.authenticationProvider(new DPoPAuthenticationProvider(...))` inline. Both constraints
are noted in #18120.

So:

1. `SharedJtiDPoPAuthenticationProvider` wraps a stock `DPoPAuthenticationProvider`. All
   default validation, including the `ath` and `jkt` checks whose validators are private
   inner classes, runs unmodified and runs **first**. Nothing security-critical is
   reimplemented here, and the shared cache is only written for proofs that are otherwise
   valid, so an unauthenticated caller cannot burn `jti` entries in Redis.
2. It then runs a second `DPoPProofJwtDecoderFactory` whose validator factory, set through
   the public seam, contains *only* the Redis validator. The default chain is deliberately
   not composed in: it has already run, and its process-local `JtiClaimValidator` would see
   its own insertion and reject every request on the second pass.
3. The wrapper is registered with `http.authenticationProvider(...)` before `http.build()`,
   so it precedes the provider the configurer installs during its configure phase.
   `ProviderManager` stops at the first provider that returns a result.

Step 3 is load-bearing and fragile, so it is asserted rather than assumed:
`SharedJtiWiringTests` boots the context and fails if the ordering ever inverts. If it did,
Redis would never be consulted and every cross-replica replay would be admitted while the
stack still looked healthy.

Cost: the proof signature is verified twice per request. D2 here carries no latency claim,
and the alternative is forking the library's validator chain.

## Layout

```
docker-compose.yml            Keycloak, Redis, 3 replicas, NGINX
resource-server.env           settings shared by the three replicas
nginx/nginx.conf              round-robin, one worker
keycloak/realm-export.json    dpop-demo realm, ES256, DPoP-bound tokens
resource-server/              Spring Boot 3.5.5 / Spring Security 6.5.5 / Java 21
correctness/cross_replica.py  the assertions
```

Host ports are offset from the single-host stack (8080, 8081, 9000) so both can run at once.

| Port | Service |
|------|---------|
| 8180 | Keycloak |
| 9100 | Keycloak management |
| 8190 | NGINX, the only entry to the replicas |
| 6479 | Redis, exposed for inspection only |

## Running

Requires Docker with Compose, and `python3` with `httpx` and `cryptography`.

```
cd measurement-matrix/d2-distributed-cache

# fact 1: default process-local cache
docker compose up -d --build
python3 correctness/cross_replica.py --mode default

# fact 2: Redis-backed shared cache
docker compose down
DPOP_JTI_CACHE=redis docker compose up -d --build
python3 correctness/cross_replica.py --mode redis

# optional, stops and restarts the redis container
python3 correctness/cross_replica.py --mode redis --with-redis-outage
```

`docker compose down` between modes is required. `DPOP_JTI_CACHE` is read at startup, and
the default-cache `jti` map is JVM state that a restart must clear.

The script reads the mode each replica reports back in `X-Jti-Cache` and aborts if it
disagrees with `--mode`, so a run cannot report a Redis result against a default-cache stack.

## What the script asserts

Preconditions, both modes:

- the token is DPoP-bound and `cnf.jkt` matches the client key
- the proxy fans out over three distinct replicas, read from `X-Node-Id`
- unique proofs are accepted on every replica

Then one proof is built and presented six times verbatim, same `jti` and same `iat`, one
second apart, all through the proxy so `htu` is identical for every presentation and a
rejection can only come from the `jti` check. Six presentations at one per second visit each
replica twice and finish 5 s after the proof was minted, far inside the 60 s `iat` window,
which is asserted.

Assertions are stated over the observed `(status, node)` sequence, not over an assumed
round-robin order. A scheduling artefact is reported INCONCLUSIVE, never PASS, and Redis
partition behaviour is reported SKIP unless `--with-redis-outage` is passed.

`--mode default` expects the first presentation accepted, at least one later presentation
accepted on a replica that never saw the proof, all three replicas admitting it, and
rejection only once it returns to a replica that has.

`--mode redis` expects exactly one acceptance and rejection everywhere else, including at
least one rejection from a replica that never saw the proof.

## Verified against real source

Read at tag `6.5.5`, not assumed:

- `DPoPProofJwtDecoderFactory` for the exact signature of `setJwtValidatorFactory`, the
  `DPoPProofContext` type parameter, `DEFAULT_JWT_VALIDATOR_FACTORY`, and the private
  `JtiClaimValidator` with its `static` `MAX_SIZE = 1000` map
- `DPoPProofContext` for the builder's required fields, `accessToken` being nullable
- `DPoPAuthenticationProvider` for `setDPoPProofVerifierFactory` and for the `ath` and `jkt`
  validators being private inner classes
- `DPoPAuthenticationConfigurer` for the inline provider construction
- `DelegatingOAuth2TokenValidator` for running every delegate with no short circuit
- `ProviderManager` for first-result-wins ordering

## Confirmed by execution

Both facts were run against the live stack; outputs are under `results/`. In the default
process-local cache one proof presented to three replicas was accepted by all three at
1 req/s and rejected only on return to a replica that had already seen it (11 passed,
1 skipped, `results/default-cache.txt`). In the Redis shared cache exactly one presentation
was accepted and every later presentation rejected, including on replicas that never saw
the proof, and the validator fails closed while Redis is down and recovers when it returns
(12 passed, `results/redis-shared-cache.txt`). The run confirmed NGINX round-robin
alternating replicas, `Host` passthrough sufficing for `htu` validation through the proxy,
and Redis fail-closed under a real outage. Latency was not measured and is not claimed.
