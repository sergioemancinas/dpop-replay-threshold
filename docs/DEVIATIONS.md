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
