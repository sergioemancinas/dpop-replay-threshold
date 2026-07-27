"""
Bootstrap BCa confidence intervals and the pre-registered replication-count rule.

Pre-registered target (PREREGISTRATION.md): "Replication count per condition
determined by CONFIRM-style pilot analysis, targeting a bootstrap BCa 95%
confidence interval width of <= +/- 5% of median p99."

Unit of observation. One replication of one condition at one load level yields one
p99 (read from that run's HdrHistogram). A pilot of n replications therefore yields
n p99 values, and the statistic of interest is the MEDIAN of those n values. The
bootstrap resamples replications, not individual requests. Resampling individual
requests would estimate the sampling error of a single run's p99 and would ignore
run-to-run variance, which is the dominant term on shared hardware.

BCa follows Efron (1987), "Better bootstrap confidence intervals", JASA 82(397):
171-185, with the bias-correction z0 from the bootstrap distribution and the
acceleration a from the jackknife influence values.

Limitations of a BCa interval:
  - The median is not a smooth statistic. The jackknife acceleration estimate is
    justified asymptotically for smooth functionals; for the median it is noisy and
    for small n it can be dominated by a single leave-one-out step. `BcaResult`
    carries a `warnings` list that flags this.
  - With small n and heavy ties, the bootstrap distribution of the median is
    lattice-valued, so the attained coverage is not exactly 95% and the interval
    endpoints sit on observed data values.
  - `degenerate=True` means z0 could not be computed (all bootstrap replicates on
    one side of the point estimate) and the interval fell back to the plain
    percentile method. That fallback is a
    deviation from the pre-registered plan.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np
from scipy.special import ndtr, ndtri

# Below this many replications the BCa acceleration term is not worth trusting.
MIN_SANE_N = 8

# Pre-registered acceptance target: half-width <= 5% of the point estimate.
TARGET_RELATIVE_HALF_WIDTH = 0.05


def median_statistic(a, axis=-1):
    """Vectorised median. Signature matches scipy.stats.bootstrap's convention."""
    return np.median(a, axis=axis)


@dataclass
class BcaResult:
    point: float
    low: float
    high: float
    confidence: float
    n: int
    n_resamples: int
    z0: float
    acceleration: float
    degenerate: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def half_width(self) -> float:
        """Larger of the two arms. BCa intervals are asymmetric by construction."""
        return max(self.point - self.low, self.high - self.point)

    @property
    def relative_half_width(self) -> float:
        if self.point == 0:
            return math.inf
        return self.half_width / abs(self.point)

    @property
    def meets_target(self) -> bool:
        return self.relative_half_width <= TARGET_RELATIVE_HALF_WIDTH

    def summary(self) -> str:
        return (
            f"point={self.point:.4g} "
            f"CI{self.confidence:.0%}=[{self.low:.4g}, {self.high:.4g}] "
            f"half-width={self.half_width:.4g} "
            f"({self.relative_half_width:.2%} of point) "
            f"n={self.n} B={self.n_resamples}"
        )


def _jackknife_acceleration(sample: np.ndarray, statistic) -> float:
    """
    Efron's a_hat from jackknife influence values.

    a = sum(u_i^3) / (6 * (sum(u_i^2))^{3/2}),  u_i = theta_bar_jack - theta_(i)

    Built as one leave-one-out matrix so `statistic` is called once, vectorised.
    """
    n = sample.size
    loo = np.empty((n, n - 1), dtype=float)
    for i in range(n):
        loo[i, :i] = sample[:i]
        loo[i, i:] = sample[i + 1:]
    theta_jack = np.asarray(statistic(loo, axis=-1), dtype=float)
    u = theta_jack.mean() - theta_jack
    den = (u ** 2).sum()
    if den == 0:
        return 0.0
    return float((u ** 3).sum() / (6.0 * den ** 1.5))


def bca_ci(
    sample,
    statistic=median_statistic,
    confidence: float = 0.95,
    n_resamples: int = 10000,
    rng=None,
) -> BcaResult:
    """
    BCa confidence interval for `statistic` of `sample`.

    `statistic` must accept (array, axis=...) and reduce along that axis, so the
    bootstrap can be done in one vectorised call. Defaults to the median, which is
    what the pre-registration asks for.

    Returns a BcaResult. Does not raise on degenerate input; sets `degenerate` and
    falls back to the percentile interval so a caller can see and report it.
    """
    sample = np.asarray(sample, dtype=float).ravel()
    n = sample.size
    if n < 2:
        raise ValueError(f"need at least 2 replications, got {n}")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be in (0, 1)")

    rng = np.random.default_rng(rng)
    warnings: list[str] = []
    if n < MIN_SANE_N:
        warnings.append(
            f"n={n} < {MIN_SANE_N}: BCa acceleration is unreliable at this size"
        )

    point = float(statistic(sample, axis=-1))

    idx = rng.integers(0, n, size=(n_resamples, n))
    boot = np.asarray(statistic(sample[idx], axis=-1), dtype=float)

    alpha = 1.0 - confidence
    z_lo = ndtri(alpha / 2.0)
    z_hi = ndtri(1.0 - alpha / 2.0)

    prop_less = float(np.count_nonzero(boot < point)) / n_resamples
    degenerate = prop_less <= 0.0 or prop_less >= 1.0
    if degenerate:
        warnings.append(
            "bootstrap distribution is one-sided about the point estimate; "
            "z0 undefined, fell back to the percentile interval"
        )
        low = float(np.quantile(boot, alpha / 2.0))
        high = float(np.quantile(boot, 1.0 - alpha / 2.0))
        return BcaResult(point, low, high, confidence, n, n_resamples,
                         z0=math.nan, acceleration=math.nan,
                         degenerate=True, warnings=warnings)

    z0 = float(ndtri(prop_less))
    a = _jackknife_acceleration(sample, statistic)

    def adjusted(z):
        denom = 1.0 - a * (z0 + z)
        if denom <= 0:
            # a*(z0+z) >= 1 pushes the endpoint past the support. Clamp and flag.
            warnings.append(
                f"BCa endpoint adjustment diverged (a={a:.4g}, z0={z0:.4g}); "
                "endpoint clamped to the percentile value"
            )
            return ndtr(z)
        return float(ndtr(z0 + (z0 + z) / denom))

    a1 = adjusted(z_lo)
    a2 = adjusted(z_hi)
    low = float(np.quantile(boot, a1))
    high = float(np.quantile(boot, a2))
    if low > high:  # possible only if the adjustment inverted the endpoints
        low, high = high, low
        warnings.append("BCa endpoints inverted and were swapped")

    return BcaResult(point, low, high, confidence, n, n_resamples,
                     z0=z0, acceleration=a, degenerate=False, warnings=warnings)


def replications_for_target_width(
    result: BcaResult,
    target: float = TARGET_RELATIVE_HALF_WIDTH,
) -> int:
    """
    Replications needed to reach `target` relative half-width, by root-n scaling.

    n_req = ceil(n_pilot * (observed_relative_half_width / target)^2)

    Assumes the half-width shrinks as 1/sqrt(n), which holds asymptotically for the
    median of an absolutely continuous distribution with positive density at the
    median. It is an extrapolation from a single pilot and it does not account for
    the pilot's own sampling error, so it is a planning figure, refined once
    once the additional replications are in hand. `empirical_replication_curve` is
    the less assumption-laden alternative.
    """
    if target <= 0:
        raise ValueError("target must be positive")
    if not math.isfinite(result.relative_half_width):
        raise ValueError("pilot relative half-width is not finite")
    if result.relative_half_width <= target:
        return result.n
    return int(math.ceil(result.n * (result.relative_half_width / target) ** 2))


@dataclass
class ReplicationCurvePoint:
    n: int
    median_relative_half_width: float
    fraction_meeting_target: float


def empirical_replication_curve(
    pilot,
    candidate_ns,
    statistic=median_statistic,
    target: float = TARGET_RELATIVE_HALF_WIDTH,
    confidence: float = 0.95,
    n_trials: int = 40,
    n_resamples: int = 2000,
    rng=None,
) -> tuple[list[ReplicationCurvePoint], int | None]:
    """
    Nested bootstrap: for each candidate n, simulate the whole CI procedure.

    For each candidate n, draw `n_trials` pseudo-pilots of size n by resampling the
    observed pilot with replacement, run BCa on each, and record the relative
    half-widths. Returns (curve, smallest_n_meeting_target). The second element is
    None if no candidate met the target.

    This treats the pilot's empirical distribution as the population, so it inherits
    the pilot's discreteness and cannot see any tail the pilot did not sample. It is
    still preferable to root-n extrapolation when the pilot is small, because it
    exercises the actual interval procedure rather than an asymptotic proxy.

    Cost is n_trials * len(candidate_ns) BCa runs, so n_resamples stays modest.
    """
    pilot = np.asarray(pilot, dtype=float).ravel()
    rng = np.random.default_rng(rng)
    curve: list[ReplicationCurvePoint] = []
    for n in sorted(candidate_ns):
        rels = []
        for _ in range(n_trials):
            pseudo = rng.choice(pilot, size=n, replace=True)
            res = bca_ci(pseudo, statistic, confidence, n_resamples, rng)
            rels.append(res.relative_half_width)
        rels_arr = np.asarray(rels, dtype=float)
        curve.append(ReplicationCurvePoint(
            n=int(n),
            median_relative_half_width=float(np.median(rels_arr)),
            fraction_meeting_target=float(np.mean(rels_arr <= target)),
        ))
    chosen = next((p.n for p in curve
                   if p.median_relative_half_width <= target), None)
    return curve, chosen


def smallest_n_with_confidence(curve, min_fraction: float = 0.80) -> int | None:
    """
    Smallest n at which at least `min_fraction` of simulated pilots hit the target.

    The median criterion in `empirical_replication_curve` picks the n where a
    coin-flip of runs meets the target. That is not what "the CI will be within 5%"
    usually means. This criterion holds most of the time and always returns an n at
    least as large.
    """
    if not 0 < min_fraction <= 1:
        raise ValueError("min_fraction must be in (0, 1]")
    return next((p.n for p in curve
                 if p.fraction_meeting_target >= min_fraction), None)
