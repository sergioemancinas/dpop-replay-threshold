# Adversarial probes

These extend the honest-traffic sweep in `../` with the cases a reviewer of the model
would demand. All are binary outcomes on the same single-host stack, run non-root. Outputs
are under `results/`.

| Probe | Question | Result |
|---|---|---|
| `iat_window_probe.py` | Is the `iat` acceptance window one-sided (60 s) or two-sided (120 s)? | Two-sided, ~120 s. A proof is accepted for `iat ± clockSkew`. |
| `t_sweep.py` | Does the admission boundary depend on rate `R`, on delay `t`, or on the product? | On the product `R·t ≈ N`. Fixing `R` and sweeping `t`, the crossover moves as `t* = N/R`: ~50 s at 20 req/s, ~25 s at 40 req/s. |
| `attacker_flood.py` | Can an attacker holding a stolen token force eviction himself? | Yes. 1000+ self-signed proofs, each rejected 401 on `jkt`, each inserting a `jti`, evict the victim proof in ~1 s at idle. Loud: all 401. |
| `cross_tenant_eviction.py` | Can eviction happen with no rejected request? | Yes. A co-tenant's 1000+ legitimate HTTP 200 requests evict a low-traffic client's `jti`, because the cache is one JVM-wide static instance with no tenant partition. Silent. |

## Why these matter

The honest sweep shows a rate threshold `R* = N/S`. These probes show that threshold is a
lower bound on the honest-traffic case, not the security boundary: the eviction budget is
an attacker-influenceable, cross-tenant shared resource, and the defensive sizing bound
must use the full two-sided window `2S` and the aggregate rate across all tenants.

Run against the single-host stack (`../docker-compose.yml up -d`).
