# Single-Host Validation

Demonstrates that Spring Security's default DPoP `jti` replay cache admits proof replay
above a derivable request rate and rejects it below.

This covers **condition D1 only**, on one host. It is not a performance benchmark and
produces no latency or capacity numbers.

## What is under test

`DPoPProofJwtDecoderFactory` installs a default validator chain of `htm`, `htu`,
`JtiClaimValidator`, `JwtIssuedAtValidator`. `JtiClaimValidator` is backed by a `static`
`LinkedHashMap` bounded at `MAX_SIZE = 1000` under an evict-eldest policy.
`JwtIssuedAtValidator` defaults to `clockSkew = Duration.ofSeconds(60)`.

Both constants were read from the 6.5.5 tag, not assumed:

- `oauth2/oauth2-jose/src/main/java/org/springframework/security/oauth2/jwt/DPoPProofJwtDecoderFactory.java`
- `oauth2/oauth2-jose/src/main/java/org/springframework/security/oauth2/jwt/JwtIssuedAtValidator.java`

`ath` and `jkt` are validated separately, in `DPoPAuthenticationProvider`.

## Method

For each rate `R`:

1. Acquire a DPoP-bound access token and assert `cnf.jkt` matches the client key.
2. Issue probe proof `P` with `jti = J` at time `T`. Expect HTTP 200.
3. Drive unique-`jti` load at sustained rate `R` for `t` seconds.
4. Replay `P` verbatim, same `jti` and same `iat`, at `T + t`.
5. Record the status. HTTP 200 means the replay was admitted.

## Why the crossover is N/t, not N/S

The probe is evicted once `R * t > N`. The replay must also still pass `iat` validation,
which requires `t < W`. The observed crossover therefore sits at `N / t`, and the paper's
`R* = N / S` is the limiting case as `t` approaches the clock-skew tolerance `S` (60 s).

The default `t = 58 s` leaves a 2 s guard against clock drift between host and container,
predicting a crossover at `1000 / 58 = 17.2` req/s rather than `1000 / 60 = 16.7`.

## Running

From the repository root, `./reproduce.sh`. To run pieces directly:

```
docker compose -f docker-compose.yml up -d --build
python3 correctness/correctness.py
cd load && python3 sweep.py --rates 5,10,15,16,17,18,19,20,25,40 --repeats 2
```

Requires `python3` with `httpx` and `cryptography`. `matplotlib` is optional and only
used for the plot.

## Verifying a run

A third party can confirm a fresh run reproduces the headline, or learn that their host
was too slow to reproduce it, without reading the JSON by hand.

Smoke test, about 3 minutes. Two rate points, one repeat, still straddling the threshold:

```
RATES=16,18 REPEATS=1 ./reproduce.sh
```

16 req/s must reject and 18 req/s must admit, so this alone crosses `N/t`. For the full
transition run `./reproduce.sh` with defaults.

Verify, from this directory, after any run:

```
python3 check_results.py
```

It re-derives every admission from the recorded rate and elapsed time, checks the
headline transition sits between 17 and 18 req/s, confirms each row sustained its target
send rate, and confirms every replay landed inside the `iat` window. It also validates
`adversarial/results/t_sweep.json` if present.

Exit codes:

- `0` claim reproduced. Every check held.
- `1` model mismatch. Throughput was sustained but an observed admission, the headline,
  the `iat` window, or the adversarial sweep disagreed with the model. The claim did not
  reproduce on this run.
- `2` host too slow. At least one row sent fewer than `0.98 * rate * t` requests, so
  insertions never reached `N` at the rates that should admit and the outcome can invert.
  This is a limitation of the host, not evidence against the claim. Re-run on a faster
  host. The verifier reports this separately and never calls it a false claim.

## Deliberate omissions

No Redis, no NGINX, no replica set. Adding any of them would replace or shard the
process-local cache, which is the object under test. The distributed conditions belong to
`../measurement-matrix/` and have been run; only the latency comparison remains.

## Load generator

A purpose-built asyncio driver, not `k6` or `wrk2`. The outcome here is binary, replay
admitted or not, so it needs no HdrHistogram capture or coordinated-omission correction.
The `k6` and `wrk2` pipeline in `../PROTOCOL.md` section 5 belongs to the latency matrix,
which has not been run.
