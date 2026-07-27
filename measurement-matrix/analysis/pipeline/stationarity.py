"""
Stationarity check: two-sample Kolmogorov-Smirnov on split halves.

Pre-registered (PREREGISTRATION.md): "Stationarity verified with the
Kolmogorov-Smirnov test on split halves of each measurement window."

The measurement window is cut at its temporal midpoint and the two halves are
compared with a two-sided two-sample KS test. Failing to reject is treated as the
window being usable. That is the pre-registered rule and `split_half_ks` implements
it literally.

Three properties of that rule:

  1. KS assumes independent observations. Consecutive request latencies are
     strongly autocorrelated (queueing, GC pauses, connection reuse), so the
     nominal p-value is anti-conservative: a perfectly stationary but
     autocorrelated series rejects far more often than 5% of the time.
     `tests/test_stationarity.py::test_autocorrelation_inflates_type_i_error`
     measures that inflation rather than hiding it. `thin=` subsamples every k-th
     observation as a mitigation, at the cost of power.
  2. At the sample sizes a load test produces (10^5 to 10^7 requests per window),
     KS rejects on differences far too small to matter. `min_detectable_shift`
     reports the KS statistic that the test can resolve at the given n, so a
     rejection can be read against a magnitude.
  3. Failing to reject is not evidence of stationarity. It is absence of evidence
     against it. A drift that is monotone but symmetric about the midpoint, or a
     change in autocorrelation with no change in marginal distribution, is
     invisible to this test.

Neither thinning nor any magnitude threshold is part of the pre-registered rule.
Using them on real data is a deviation and belongs in docs/DEVIATIONS.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy.stats import ks_2samp

# Asymptotic 5% critical coefficient for the two-sided two-sample KS statistic.
# D_crit = c(alpha) * sqrt((n1 + n2) / (n1 * n2)); c(0.05) = 1.358.
KS_CRITICAL_COEFFICIENT = {0.10: 1.224, 0.05: 1.358, 0.01: 1.628}


@dataclass
class SplitHalfResult:
    statistic: float
    pvalue: float
    n_first: int
    n_second: int
    alpha: float
    thin: int
    min_detectable_shift: float
    median_first: float
    median_second: float

    @property
    def rejects_stationarity(self) -> bool:
        """True when the pre-registered test says the window is not stationary."""
        return self.pvalue < self.alpha

    def summary(self) -> str:
        verdict = "NON-STATIONARY" if self.rejects_stationarity else "stationary"
        return (
            f"KS D={self.statistic:.4g} p={self.pvalue:.4g} "
            f"n=({self.n_first}, {self.n_second}) thin={self.thin} "
            f"median {self.median_first:.4g} -> {self.median_second:.4g} "
            f"D_crit({self.alpha:g})={self.min_detectable_shift:.4g} "
            f"verdict={verdict}"
        )


def min_detectable_shift(n1: int, n2: int, alpha: float = 0.05) -> float:
    """Asymptotic critical value of the two-sample KS statistic at level alpha."""
    if alpha not in KS_CRITICAL_COEFFICIENT:
        raise ValueError(f"alpha must be one of {sorted(KS_CRITICAL_COEFFICIENT)}")
    if n1 <= 0 or n2 <= 0:
        return math.inf
    return KS_CRITICAL_COEFFICIENT[alpha] * math.sqrt((n1 + n2) / (n1 * n2))


def split_half_ks(
    values,
    timestamps=None,
    alpha: float = 0.05,
    thin: int = 1,
) -> SplitHalfResult:
    """
    Split a measurement window in half and KS-test the two halves.

    values      per-request observations in acquisition order.
    timestamps  optional, same length. If given the split is at the temporal
                midpoint (t_min + t_max) / 2 rather than the index midpoint. This
                matters when the request rate is not constant, where the index
                midpoint is not the time midpoint.
    thin        keep every k-th observation before testing. NOT pre-registered.
    """
    values = np.asarray(values, dtype=float).ravel()
    if thin < 1:
        raise ValueError("thin must be >= 1")
    if values.size < 4:
        raise ValueError(f"need at least 4 observations, got {values.size}")

    if timestamps is None:
        cut = values.size // 2
        first, second = values[:cut], values[cut:]
    else:
        timestamps = np.asarray(timestamps, dtype=float).ravel()
        if timestamps.size != values.size:
            raise ValueError("timestamps and values must have the same length")
        midpoint = 0.5 * (timestamps.min() + timestamps.max())
        mask = timestamps <= midpoint
        first, second = values[mask], values[~mask]

    if thin > 1:
        first, second = first[::thin], second[::thin]
    if first.size < 2 or second.size < 2:
        raise ValueError(
            f"split produced halves of size {first.size} and {second.size}"
        )

    res = ks_2samp(first, second, alternative="two-sided")
    return SplitHalfResult(
        statistic=float(res.statistic),
        pvalue=float(res.pvalue),
        n_first=int(first.size),
        n_second=int(second.size),
        alpha=alpha,
        thin=thin,
        min_detectable_shift=min_detectable_shift(first.size, second.size, alpha),
        median_first=float(np.median(first)),
        median_second=float(np.median(second)),
    )
