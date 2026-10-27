# Deviations from the Pre-Registered Plan

Any departure from `PREREGISTRATION.md` is recorded here with a date and a reason.

## Record

| Date | Deviation | Reason |
|------|-----------|--------|
| 2026-07-27 | Single-host validation replays the probe at `t = 58 s` rather than at the window edge `W = 60 s`, so the predicted crossover is `N/t = 17.2` req/s rather than `N/W = 16.7` req/s. | A replay issued exactly at the window edge is decided by sub-second clock drift between host and container. The 2 s guard band makes the outcome deterministic. The analytical claim is unchanged: `N/W` remains the limiting case as `t` approaches `W`. |
| 2026-07-27 | Single-host validation uses a purpose-built asyncio load driver rather than `k6` or `wrk2`. | The outcome is binary, replay admitted or not. HdrHistogram capture and coordinated-omission correction exist to characterise latency distributions and are not applicable. `k6` and `wrk2` remain the tools for the unexecuted latency matrix. |

## Pre-registered analysis plan: known defect, not yet amended

The pre-registered stationarity rule is *"Stationarity is verified using the
Kolmogorov-Smirnov test on split halves of each measurement window."* Building the
pipeline before collecting data exposed a problem with it.

Split-half KS assumes independent samples. Latency series are strongly autocorrelated. On
400 AR(1) series that are **stationary by construction**, the rule rejects:

| autocorrelation | rejection rate | nominal |
|---|---|---|
| phi = 0.0 | 3.0% | 5% |
| phi = 0.5 | 22.0% | 5% |
| phi = 0.95 | 88.5% | 5% |
| phi = 0.95, thinned every 40th sample | 7.2% | 5% |

Applied literally to real latency data, the rule would discard most valid measurement
windows and introduce a severe selection effect, biasing whatever survived.

This is recorded rather than silently fixed. Amending a pre-registered analysis plan
after seeing data is what pre-registration exists to prevent, and no data has been
collected yet, so the amendment can still be made honestly. Any replacement rule, whether
thinning to the autocorrelation length, a block-bootstrap stationarity test, or an
explicitly descriptive-only screen, must be committed here **before** the first latency
measurement run.

Other limitations of the pre-registered plan, documented in
`measurement-matrix/analysis/README.md` and not yet resolved:

- The "+/- 5% CI width" replication criterion is ambiguous. Read as a median criterion it
  gives n = 30, of which only 57% of pilots actually achieve 5%. Read as an 80%-confidence
  criterion it gives n = 60. The pre-registration does not say which is meant.
- The plan does not state whether the omnibus test operates on per-replication p99 values
  (n of order 20) or pooled per-request latencies (n of order 10^6). These are different
  tests with different independence structure. The caller must decide and record this
  before seeing data.
- Kruskal-Wallis and Dunn are not tests of medians unless the groups share a distribution
  shape, which bearer, DPoP and mTLS latency distributions are unlikely to do.
- BCa on a median is the weakest component of the pipeline: jackknife acceleration is
  justified for smooth functionals and the median is not one.

Work that has not run yet is listed in the execution status table in
`PREREGISTRATION.md`, not here.

## Commit timestamps

The paper's Appendix A states that the pre-registration commit `53e4ae2` (dated
2026-07-27 12:34:48 UTC) precedes the first commit with measured data, `bbd4d22` (dated
13:20:35 UTC), and that this ordering is verifiable from the repository history. It is not:

- `bbd4d22` contains `single-host-validation/results/environment.txt`, which
  `reproduce.sh` writes at the end of a run and which records `2026-07-27T16:34:15Z`,
  three hours after the commit's own date.
- The GitHub repository was created at 2026-07-27 19:00:05 UTC, after both commits
  existed, so neither was public at its stated time.

The commit dates therefore do not reflect when the contents were written, and the author
cannot reconstruct how they were produced. Nothing is rewritten here; the history is left
as it is.

What this affects: only the claim of a verifiable ordering. The single-host result of
Sec. V-D is a deterministic outcome predicted from the Spring Security source and does not
rest on pre-registration. H1–H4 have not been run. Release `v1.0.0`, archived on Zenodo on
2026-10-27 ([doi:10.5281/zenodo.23687980](https://doi.org/10.5281/zenodo.23687980)), gives
`PREREGISTRATION.md` an independent timestamp; no H1–H4 data predates it.

## Post-publication code changes

Changes to code that existed at publication (`v1.0.0`). None changes a committed result.

| Date | Change | Reason |
|------|--------|--------|
| 2026-10-27 | D4 `DPoPNonceStore.consume` checks the key binding before spending the nonce, and spends it with a conditional remove. A test now asserts that a wrong-key attempt leaves the nonce usable for its owner; it fails on the old code. | The old code removed the nonce first, so a request under another key burned the nonce of the client it was issued to. Single use and key binding were already enforced; this only removes the burn. |
| 2026-10-27 | D2 Redis TTL raised from 120 s to 125 s. | 120 s is tight only with synchronised clocks. Each replica checks `iat` on its own clock while Redis expires the key on its clock; the 5 s margin covers offset between them. The D2 results replay within seconds of first use, so their outcome does not depend on the TTL. |
| 2026-10-27 | CI builds every resource server and runs the Maven test suites. | They were previously run by hand only. |
