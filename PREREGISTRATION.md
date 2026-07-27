# Pre-Registration

This document states the measurement design and falsifiable hypotheses **before any
data collection**. It is committed prior to the first measurement run. The commit hash
of this file's introducing commit is the pre-registration record referenced in the
accompanying paper.

Any deviation from the analysis plan below is disclosed in the paper's threats-to-validity
section and recorded in `docs/DEVIATIONS.md`.

## Scope of what is pre-registered

The analytical result (the bounded-cache replay threshold `R* = N / W`) is **not** part of
this pre-registration. It is derived from published library source and is established
independently of any measurement. What is pre-registered here is the empirical programme:
the single-host validation of that analytical result, and the broader DPoP-versus-mTLS
cost comparison.

## Hypotheses

**H1:** Distributed cache (D2) increases p99 by >= 1 ms over D1 below 1000 requests per
second.

**H2 (headline):** There exists a request rate lambda* per resource-server connection at
which D2 p99 crosses M1 p99 from below, given session reuse, or no such crossover exists.

**H3:** D4 reduces p99 variance compared to D2 by >= 20%.

**H4:** A closed-form prediction `p99(lambda, r) = a + b*lambda + c*(r-1)*log(lambda)` fits
observed data within +/- 15%, where r is replica count.

## Conditions

| ID | Condition |
|----|-----------|
| C0 | Bearer baseline (no proof, no certificate) |
| D1 | DPoP with single-node Spring Security default cache |
| D2 | DPoP with three-replica Redis-distributed cache |
| D4 | DPoP with server-provided nonces (RFC 9449 Sec. 8) |
| M1 | mTLS certificate-bound access tokens |
| X1 | Correct X-Forwarded-Client-Cert propagation (silent-binding control) |
| X2 | Broken X-Forwarded-Client-Cert URL-encoding mismatch (silent-binding demonstration) |

## Load levels

Three per condition: *low* (well below saturation), *knee* (p99 begins to deviate
non-linearly), *saturation* (error rate exceeds 1%).

## Statistical analysis plan

- Replication count per condition determined by CONFIRM-style pilot analysis, targeting a
  bootstrap BCa 95% confidence interval width of <= +/- 5% of median p99.
- Stationarity verified with the Kolmogorov-Smirnov test on split halves of each
  measurement window.
- Kruskal-Wallis omnibus comparison, followed by Dunn post-hoc pairwise tests with Holm
  correction.
- Effect sizes reported as Cliff's delta with Romano-Kromrey thresholds.
- Coordinated-omission correction applied client-side per wrk2. Server-side coordinated
  omission is disclosed as a threat to validity, not corrected.

## Correctness suite

Run before any benchmark measurement. Validates:

- `jti` rejection on second use, within and across replicas
- stale-proof rejection under clock skew of +/- 2 seconds
- TTL edge behaviour at expiry-minus-1s and expiry-plus-1s
- `ath` and `htm`/`htu` mismatch rejection
- partition behaviour under Redis primary loss (fail-closed expected)
- bounded-cache replay admission above `R*`

## Execution status

| Component | Status |
|-----------|--------|
| Single-host validation of `R*` (subset of D1) | in this repository, see `single-host-validation/` |
| Full condition matrix C0/D1/D2/D4/M1/X1/X2 | not executed, future work |
| H1, H2, H3, H4 | not tested, future work |

Hypotheses H1-H4 require the full distributed topology. No outcome for them is claimed
anywhere in this repository or in the accompanying paper.
