# Statistical analysis pipeline

**Status: no measurement data exists. This directory contains the analysis, not
results.**

The condition matrix in `PROTOCOL.md` section 3 has not been executed. Nothing in
this directory has ever been pointed at a real `wrk2` or `k6` run, a real Keycloak,
or a real resource server. Every number the pipeline has produced came from
`pipeline/synthetic.py` or from the fixtures under `tests/fixtures/`, all of which
are named `SYNTHETIC` and carry a banner in their own comment syntax.

The point of building it now is that the analysis plan in `PREREGISTRATION.md` is
committed before data collection, so the code implementing it should be committed
and validated before data collection too. If the pipeline had been written after the
numbers arrived, every choice in it would be a researcher degree of freedom.

`run_synthetic_validation.py` exercises the whole path end to end and prints to
stdout. It writes no files, deliberately.

## Contents

```
pipeline/bca.py            BCa bootstrap CI, replication-count rule
pipeline/stationarity.py   split-half Kolmogorov-Smirnov
pipeline/omnibus.py        Kruskal-Wallis, Dunn post-hoc, Holm correction
pipeline/effect_size.py    Cliff's delta, Romano-Kromrey magnitudes
pipeline/hdr.py            HdrHistogram reader, wrk2 and k6 ingestion
pipeline/synthetic.py      synthetic generators (fabricated on purpose)
pipeline/report.py         runs the above in the pre-registered order
tests/                     145 tests, all against known-answer cases
tests/fixtures/            SYNTHETIC fixtures + the script that regenerates them
run_synthetic_validation.py  end-to-end smoke run on synthetic input
```

Requires numpy and scipy. Developed against numpy 1.26.4, scipy 1.17.0,
pytest 9.0.2, CPython 3.11. scipy is used where it has the statistic
(`kruskal`, `ks_2samp`, `mannwhitneyu`, `bootstrap`, `rankdata`, `ndtr`/`ndtri`).
Dunn's test and Holm's correction are hand-rolled because scipy has neither and
`scikit-posthocs` is not a dependency worth adding for two short functions.

```
pip install -r requirements.txt
python3 -m pytest tests -q
python3 run_synthetic_validation.py
```

## Mapping to the pre-registered plan

| `PREREGISTRATION.md` line | Implementation |
|---|---|
| bootstrap BCa 95% CI, half-width <= 5% of median p99 | `bca.bca_ci`, `bca.replications_for_target_width`, `bca.empirical_replication_curve` |
| KS on split halves of each measurement window | `stationarity.split_half_ks` |
| Kruskal-Wallis omnibus | `omnibus.kruskal_wallis` |
| Dunn post-hoc, Holm correction | `omnibus.dunn_posthoc`, `omnibus.holm_adjust` |
| Cliff's delta, Romano-Kromrey thresholds | `effect_size.cliffs_delta`, `effect_size.romano_kromrey_magnitude` |
| HdrHistogram capture from wrk2 / k6 | `hdr.*` |
| client-side coordinated-omission correction | not implemented here; `wrk2` does it. `hdr.parse_wrk2_latency_summary` returns the corrected and uncorrected blocks separately and labelled, so the corrected series cannot be substituted by accident |

## Function reference

### `pipeline/bca.py`

**`bca_ci(sample, statistic=median_statistic, confidence=0.95, n_resamples=10000, rng=None) -> BcaResult`**

Bias-corrected and accelerated bootstrap interval, per Efron (1987), "Better
bootstrap confidence intervals", *JASA* 82(397): 171-185. `z0` from the proportion
of bootstrap replicates strictly below the point estimate; acceleration `a` from
jackknife influence values. `statistic` takes `(array, axis=...)` and reduces along
that axis, matching `scipy.stats.bootstrap`'s vectorised convention.

*Unit of observation.* One replication yields one p99. The bootstrap resamples
**replications**, not requests. Resampling requests would estimate the sampling
error of one run's p99 and would ignore run-to-run variance, which dominates on
shared hardware.

*Assumptions.* Replications are iid draws from a stable population. Any warm-up,
ordering, or same-host correlation between consecutive replications violates that
and the interval will be too narrow. Randomise condition order across replications.

*Limitations.* The median is not smooth, so the jackknife acceleration is
asymptotically justified but noisy in practice, and at small `n` a single
leave-one-out step can dominate it. The bootstrap distribution of a median is
lattice-valued, so the endpoints land on observed data values and attained coverage
is not exactly 95%. `BcaResult.warnings` flags `n < 8`. `BcaResult.degenerate` is set
when `z0` is undefined (all replicates on one side of the estimate) and the interval
falls back to the plain percentile method; if that ever fires on real data it is a
deviation and belongs in `docs/DEVIATIONS.md`.

`BcaResult.half_width` is the **larger** of the two arms, because BCa intervals are
asymmetric and reporting the average would understate the worse side.

**`replications_for_target_width(result, target=0.05) -> int`**

`ceil(n_pilot * (observed_relative_half_width / target)^2)`. Assumes root-*n*
shrinkage, which holds asymptotically for the median of an absolutely continuous
distribution with positive density there. It is an extrapolation from one pilot and
carries none of that pilot's own uncertainty. Planning figure only; re-check once the
extra replications exist.

**`empirical_replication_curve(pilot, candidate_ns, ...) -> (curve, chosen_n)`**

Nested bootstrap. For each candidate `n`, draw `n_trials` pseudo-pilots of size `n`
from the observed pilot and run the real BCa procedure on each. Less
assumption-laden than root-*n* extrapolation, but it treats the pilot's ECDF as the
population, so it cannot see a tail the pilot never sampled.

`chosen_n` is the smallest `n` whose **median** relative half-width meets the target.
That is a weak criterion: on the validation pilot, `n = 30` was chosen while only
57% of simulated pilots at `n = 30` actually met 5%. Use
**`smallest_n_with_confidence(curve, min_fraction=0.80)`** when the claim needs to
hold most of the time. On the same pilot that returns `n = 60` (90% of pilots meet
the target) rather than 30.

### `pipeline/stationarity.py`

**`split_half_ks(values, timestamps=None, alpha=0.05, thin=1) -> SplitHalfResult`**

Cuts the measurement window in half and runs a two-sided two-sample KS test.
`rejects_stationarity` is `p < alpha`, which is the pre-registered rule, implemented
literally. With `timestamps`, the split is at the temporal midpoint rather than the
index midpoint; use it whenever the arrival rate is not constant, since the two are
different cuts.

*Assumptions.* KS assumes independent observations and a continuous distribution.
Request latencies satisfy neither: they are autocorrelated, and if reconstructed from
a histogram they are heavily tied.

*Limitations, all of them consequential.*

- **Autocorrelation inflates the false-positive rate.** Measured, not assumed:
  `test_autocorrelation_inflates_type_i_error` runs 200 stationary AR(1) series with
  phi = 0.95 and the split-half test rejects **88%** of the time against a nominal
  5%. On real latency traces the pre-registered test will therefore condemn windows
  that are fine. `thin=k` subsamples every k-th observation and pulls the rate back to nominal
  (86.5% unthinned, 5.0% at `thin=40` on 4000-point AR(1) series), at a cost in
  power. **Thinning is not
  pre-registered**; using it on real data is a deviation.
- **At load-test sample sizes the test rejects on nothing.** At 10^6 requests per
  half, `min_detectable_shift` is about 0.002, so a difference of no operational
  consequence is significant. `SplitHalfResult` reports `statistic` and
  `min_detectable_shift` side by side so a rejection can be read against a
  magnitude. Introducing a magnitude gate would also be a deviation.
- **Failing to reject is not evidence of stationarity.** Symmetric drift about the
  midpoint, or a change in autocorrelation with no change in the marginal, is
  invisible.

**`min_detectable_shift(n1, n2, alpha=0.05) -> float`**

Asymptotic KS critical value, `c(alpha) * sqrt((n1+n2)/(n1*n2))`, with
c = 1.224 / 1.358 / 1.628 for alpha = 0.10 / 0.05 / 0.01.

### `pipeline/omnibus.py`

**`kruskal_wallis(groups, labels=None, alpha=0.05) -> KruskalResult`**

Thin wrapper over `scipy.stats.kruskal` (tie-corrected).

*Limitation.* Kruskal-Wallis tests stochastic dominance, not equality of medians. It
is a median test only under the extra assumption that all groups share a shape and
scale, which latency distributions under different conditions do not. Read a
significant `H` as "at least one condition stochastically dominates another".

**`dunn_posthoc(groups, labels=None, alpha=0.05) -> DunnResult`**

Dunn (1964), "Multiple comparisons using rank sums", *Technometrics* 6(3): 241-252.
On ranks pooled across **all** groups:

```
z_ij = (Rbar_i - Rbar_j) / sqrt((A - T) * (1/n_i + 1/n_j))
A    = N(N+1)/12
T    = sum_over_tied_groups(t^3 - t) / (12(N-1))
```

Pooled ranking is what makes this a post-hoc for Kruskal-Wallis rather than a series
of independent Mann-Whitney tests; `test_dunn_uses_pooled_ranks_not_pairwise_ranks`
pins that. `z` is signed: positive means group `a` has the higher mean rank, so for
latency it is the slower one.

*Limitations.* Normal approximation, unreliable below about `n_i = 5` (flagged in
`DunnResult.warnings`). Raises if the pooled sample is entirely tied.

**`holm_adjust(pvalues) -> ndarray`**

Holm (1979), "A simple sequentially rejective multiple test procedure",
*Scandinavian Journal of Statistics* 6(2): 65-70. Step-down with a running maximum
so adjusted values are monotone in the sorted raw values, clipped at 1, returned in
input order.

*Limitation.* Holm controls the family-wise error rate over the p-values passed in
**one** call. Running `dunn_posthoc` separately per load level and then presenting
all the pairs together silently enlarges the family. Fix the family before running.

### `pipeline/effect_size.py`

**`cliffs_delta(x, y) -> CliffsDelta`**

Cliff (1993), "Dominance statistics: Ordinal analyses to answer ordinal questions",
*Psychological Bulletin* 114(3): 494-509.

```
delta = ( #{x_i > y_j} - #{x_i < y_j} ) / (n_x * n_y)
```

Ties contribute zero. Computed as `2U/(n_x n_y) - 1` from scipy's Mann-Whitney `U`
(O(n log n)); `cliffs_delta_bruteforce` is the O(n_x n_y) definitional version, kept
for tests.

**Romano-Kromrey thresholds, exactly as used:**

| `\|delta\|` | magnitude |
|---|---|
| `< 0.147` | negligible |
| `>= 0.147` and `< 0.330` | small |
| `>= 0.330` and `< 0.474` | medium |
| `>= 0.474` | large |

Source: Romano, J., Kromrey, J. D., Coraggio, J., & Skowronek, J. (2006).
*Appropriate statistics for ordinal level data: Should we really be using t-test and
Cohen's d for evaluating group differences on the NSSE and other surveys?* Annual
meeting of the Florida Association of Institutional Research, 1-3 February 2006,
Cocoa Beach, Florida. The cut-points are Cohen's d benchmarks (0.2, 0.5, 0.8)
translated onto the dominance scale.

Boundary convention: lower bound inclusive, upper bound exclusive, so `0.147` is
"small" and `0.474` is "large". The literature does not standardise this; it is
stated here rather than left to the reader, and pinned by
`test_romano_kromrey_boundaries_exact`.

*Limitations.* Cliff's delta is invariant to any monotone transform, which is why it
suits latency and also why it says nothing about milliseconds. Always report the
median difference next to it. It measures dominance, not location: equal medians with
different spread can still give a non-zero delta. The magnitude labels are
conventions from social-science survey work and carry no operational meaning for a
resource server; a "negligible" delta can still be an unacceptable p99 regression,
and a "large" delta can be 40 microseconds. The synthetic run makes the mismatch
visible: C0 vs D1 comes out `n.s.` under Dunn/Holm while its delta is -0.545,
labelled "large".

**`cliffs_delta_ci(x, y, confidence=0.95, ...)`** adds a percentile bootstrap
interval. **Not pre-registered.** Report as supplementary. Percentile rather than
BCa because the jackknife for a two-sample dominance statistic is not the
leave-one-out of a single sample that `bca.py` assumes.

### `pipeline/hdr.py`

#### Implemented subset of the HdrHistogram format

Supported:

1. **V2 binary encoding, uncompressed.** Cookie base `0x1C849303`. 40-byte
   big-endian header: cookie, payload length, normalizing index offset, significant
   digits, lowest discernible value, highest trackable value, integer-to-double
   conversion ratio. Payload is ZigZag LEB128; positive means a bucket count,
   negative means a run of that many empty buckets.
2. **V2 compressed.** Cookie base `0x1C849304`, 4-byte compressed length, then a
   zlib stream (Java `Deflater` default is zlib-wrapped) of the uncompressed V2
   form. This is what appears base64-encoded in `.hlog` files.
3. **`.hlog` interval logs.** `#` comments, optional CSV legend,
   `[Tag=name,]start,length,max,base64histogram` data lines.
4. **`outputPercentileDistribution` text**, the four-column table plus `#[Mean=...]`,
   `#[Max=...]`, `#[Buckets=...]` footers. This is wrk2's "Detailed Percentile
   spectrum".
5. **wrk2 `--latency` summary blocks**, with `us`/`ms`/`s`/`m`/`h` suffixes,
   normalised to milliseconds. Corrected and uncorrected blocks are returned
   separately with their labels.
6. **k6 `--out json`** newline-delimited output. Not HdrHistogram; k6 emits raw
   metric points. Included because `PROTOCOL.md` names k6.

Not supported, and raising rather than guessing:

- **V0 and V1 encodings** (`0x1C849300`-`0x1C849302`). Every current release writes
  V2.
- **DoubleHistogram.** `integer_to_double_value_conversion_ratio` is parsed and any
  value other than `1.0` raises, because applying it needs the auto-ranging logic
  that is not here.
- **Non-zero `normalizing_index_offset`** (a `Recorder`-rebased histogram).
- **Merging across differing lowest/highest/significant parameters.** `merge()`
  requires identical parameters.
- Concurrent, atomic, packed and all-values-recorded variants.
- General-purpose writing. `encode()`, `to_base64()` and
  `output_percentile_distribution()` exist so the decoder can be round-tripped and
  so fixtures can be generated.

#### Key functions

**`HdrHistogram(lowest_discernible_value=1, highest_trackable_value=..., significant_figures=3)`**
Bucketing follows the reference implementation exactly (unit magnitude, sub-bucket
half count, counts-array index mapping), so percentiles agree with what the Java or C
library reports for the same counts.

**`get_value_at_percentile(p)`** uses the reference rule:
`count_at = floor(p/100 * total + 0.5)`, at least 1, then the **highest** equivalent
value of the bucket reached (**lowest** at `p = 0`). That is why HdrHistogram
percentiles are conservative: never below the true order statistic, never above it by
more than one bucket width. Verified against true order statistics in
`test_percentile_respects_the_precision_guarantee`.

**`decode_histogram(bytes_or_base64)`**, **`parse_hlog(path_or_text)`**,
**`merge_hlog(intervals)`**.

**`parse_percentile_distribution(path_or_text)`** returns a `PercentileDistribution`.
`value_at_percentile(p)` is a **step lookup rounded up to the next tabulated row**;
there is no interpolation, since interpolating would invent precision the table does
not have.

> **Read a p99 out of a `.hlog`, not out of a percentile dump.** The spectrum is a
> re-rendering at HdrHistogram's tick schedule (five ticks per halving of the
> remaining distance to 100%), so near p99 the rows are about 0.16 percentile points
> apart. On the synthetic fixture the true p99 is 12.343 ms and the dump's next row
> up is 13.495 ms, a 9% overshoot. `bracket_at_percentile(p)` returns the two rows
> straddling `p` so the coarseness is visible instead of silent. This is a property
> of the format, not of the parser.

**`parse_wrk2_latency_summary(path_or_text)`** returns one `Wrk2LatencyBlock` per
`Latency Distribution (HdrHistogram - <label>)` block, values in ms.
`value_at_percentile` raises `KeyError` for any percentile wrk2 did not tabulate,
rather than interpolating between the fixed rows.

**`parse_k6_json_stream(path_or_text, metric="http_req_duration", with_time=False)`**
reads `{"type":"Point",...}` records. With `with_time`, returns seconds since the
first point, which is what `split_half_ks(timestamps=...)` wants.

**`samples_from_histogram(hist)`** expands counts back to one value per observation,
each at its bucket's median-equivalent value. Needed because KS and Cliff's delta
take samples, not counts. **Lossy in a way that matters:** a 10^6-request histogram
collapses to a few thousand distinct values with enormous tie counts
(`test_samples_from_histogram_is_heavily_tied` shows fewer than 5% distinct), and
KS's null distribution assumes continuity. Raw per-request samples are the accurate
input for KS; expanding a histogram is a lossy fallback and is recorded as such where used.

### `pipeline/report.py`

Runs the steps in a fixed order so the order cannot drift once data arrives:
stationarity, then per-condition CI and replication rule, then omnibus, then post-hoc
**only if the omnibus rejects**, then effect sizes **regardless of significance**.
`compare_conditions` refuses to run the post-hoc after a non-significant omnibus.
Effect sizes are deliberately not gated on p-values; gating them is how effect-size
literatures acquire a bias.

## Validation

145 tests, all against cases with known answers. `python3 -m pytest tests -q`.

Statistics checked against an **independent reference implementation**:

| Statistic | Reference |
|---|---|
| BCa interval (mean and median) | `scipy.stats.bootstrap(method="BCa")`, agreement within 3% (mean) and 10% (median) of the interval width |
| BCa acceleration | closed form `sum(d^3) / (6 (sum d^2)^{3/2})` for the mean, derived by hand in the test docstring |
| Dunn's z | the identity that for k = 2 Dunn's z equals the tie-corrected Mann-Whitney normal-approximation z exactly, using `scipy.stats.mannwhitneyu`'s U and a textbook variance; derivation in `test_dunn_two_groups_equals_mannwhitney_z`. Machine precision, with and without ties |
| Cliff's delta | `2U/(n_x n_y) - 1` from `scipy.stats.mannwhitneyu`, and an O(n_x n_y) brute-force count written from the definition |
| Kruskal-Wallis | `scipy.stats.kruskal`, itself checked against two hand-computed H values (one with ties) |
| KS | `scipy.stats.ks_2samp`, checked against two hand-computed D values and the exact combinatorial p-value 2/70 for disjoint 4-vs-4 halves |
| HdrHistogram percentiles | true order statistics of the input, held to the library's own 10^-significant_figures precision contract |

Checked against **independently computed expected values**:

- Replication count: for a normal population the asymptotic SE of the median is
  `sqrt(pi/2) * sigma / sqrt(n)`, so the n at which the relative half-width first
  reaches 5% of a mean of 100 with sigma 10 is
  `(1.96 * 1.2533 * 10 / 5)^2 = 24.13`. The nested-bootstrap curve returns 30, inside
  the required factor of two, and conservative in the right direction.
- Cliff's delta for two normals separated by `d` sigma: `2*Phi(d/sqrt(2)) - 1`.
  d = 1.0 gives 0.5205 ("large"), d = 0.3 gives 0.1680 ("small"); both recovered to
  within 0.02 from 20k-40k samples.
- Holm on `[0.010, 0.020, 0.030, 0.040]` gives `[0.040, 0.060, 0.060, 0.060]`,
  including the monotonicity lift on the last element.
- BCa coverage of the true median `exp(1)` of a lognormal(1, 0.5) population:
  300 trials at n = 40, coverage required in [0.88, 0.995].

Negative controls, which must **not** come out significant:

- four groups drawn from the same normal: Kruskal-Wallis n.s., no Dunn pair
  significant, every Cliff's delta "negligible";
- two identical halves of a window: KS D = 0, p = 1;
- iid window: split-half KS rejection rate 1-10% over 400 trials;
- two large samples from the same normal: `|delta| < 0.05`, bootstrap CI covers 0.

Known-answer positive controls: planted mean shift, planted linear drift, planted
condition ordering, complete dominance and complete subordination for delta = +1/-1.

### What is *not* independently validated

**The HdrHistogram V2 container is round-tripped through this module's own encoder.**
No blob produced by the Java, C or Go reference implementation was available offline,
so a symmetric bug in the encoder and the decoder would pass every test. Mitigations,
which narrow the gap without closing it: the header is asserted field by field
against the documented byte offsets; the compressed wrapper is asserted to be plain
zlib; the base64 prefix is asserted to be `HISTFAAA`, which is what real `.hlog`
files begin with; and the bucket arithmetic is checked against hand-computed indices
and against true order statistics, which is independent of the container entirely.
**Before real data is analysed, decode one histogram produced by an actual `wrk2`
run and compare its p99 against `wrk2`'s own printed p99.** Until then treat the
container as unproven.

## Open specification gaps

Things `PREREGISTRATION.md` does not pin down, which must be decided and recorded in
`docs/DEVIATIONS.md` before real data is analysed. Deciding them after seeing the
data would defeat the pre-registration.

1. **What the omnibus operates on.** Per-replication p99 values (n = replications) or
   pooled per-request latencies (n = millions)? These are different tests with
   different independence structure, and the second is significant for essentially
   any difference. This module is agnostic; the caller must fix it.
2. **The family for the Holm correction.** Pairs within one load level, or all pairs
   across all three load levels? The pre-registration says "Dunn post-hoc with Holm
   correction" without naming the family.
3. **The 5% target is a median criterion.** "CI width <= +/- 5% of median p99" does
   not say whether that must hold for the realised interval or in expectation. See
   `smallest_n_with_confidence`.
4. **Which wrk2 series feeds the analysis.** The corrected block is the pre-registered
   one, but the parser returns both and nothing in the plan forbids mixing them.
5. **Whether a window that fails the stationarity check is discarded or re-run.** The
   pipeline reports the failure and does not decide. Discarding windows that fail a
   test with a measured 88% false-positive rate under autocorrelation would be a
   serious selection effect.

## Objections a statistician should raise

Listed so they are not discovered later.

- **BCa on a median is the weakest part.** The acceleration term is estimated by
  jackknife, which is justified for smooth functionals. For a median it is noisy, and
  the bootstrap distribution is lattice-valued. The intervals here are usable but
  their attained coverage is not exactly 95%. A smoothed bootstrap or a
  distribution-free order-statistic interval for the median would be defensible
  alternatives; both would be deviations from the pre-registered plan.
- **Split-half KS is the wrong test for this data.** It assumes independence, which
  request latency violates badly. The measured type-I error under a stationary
  AR(1) with phi = 0.95 is 88%, not 5%. The pre-registered rule is implemented as
  written, but it should be read as a coarse screen, not a stationarity guarantee.
- **Kruskal-Wallis and Dunn are not median tests** unless the group distributions
  share a shape. Latency distributions under bearer, DPoP and mTLS almost certainly
  do not.
- **Romano-Kromrey labels are imported conventions** with no operational meaning for
  latency. They should never appear without the corresponding millisecond
  difference.
- **The replication-count rule extrapolates from one pilot** and does not propagate
  the pilot's own uncertainty. Two pilots of the same condition can easily disagree
  by a factor of two on the required n.
- **Nothing here corrects for multiple conditions x multiple load levels x four
  hypotheses.** Holm is applied within one post-hoc call only. H1-H4 are separately
  pre-registered hypotheses, which is a defence, but the total number of tests run
  should be stated in the paper.
- **Server-side coordinated omission is not corrected**, per `PROTOCOL.md` section 5.
  It is disclosed as a threat to validity. Client-side correction is `wrk2`'s, not
  this pipeline's, and the pipeline cannot verify it happened; it can only keep the
  corrected and uncorrected series apart.

## Regenerating fixtures

```
python3 tests/fixtures/make_fixtures.py
```

Writes `SYNTHETIC_NOT_A_MEASUREMENT_wrk2.txt`, `SYNTHETIC_NOT_A_MEASUREMENT.hlog`
and `SYNTHETIC_NOT_A_MEASUREMENT_k6.json`. The wrk2 fixture is built so its order
statistics are exact: the 50000th of 100000 values is 1050 us and the 99000th is
12340 us, which HdrHistogram reports as 1050 us and 12343 us respectively. The
fixtures are fabricated and named accordingly. Do not remove the banners.
