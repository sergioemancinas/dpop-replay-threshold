"""
Cliff's delta with Romano-Kromrey magnitude thresholds.

Pre-registered (PREREGISTRATION.md): "Effect sizes reported as Cliff's delta with
Romano-Kromrey thresholds."

Cliff (1993), "Dominance statistics: Ordinal analyses to answer ordinal questions",
Psychological Bulletin 114(3): 494-509.

    delta = ( #{x_i > y_j} - #{x_i < y_j} ) / (n_x * n_y)      in [-1, +1]

delta = +1 means every x exceeds every y. delta = 0 means the two samples are
stochastically indistinguishable in the dominance sense. Ties contribute zero to the
numerator, which is the definition used here and by every implementation the
literature cites.

MAGNITUDE THRESHOLDS. The exact cut-points used are:

    |delta| <  0.147   negligible
    |delta| <  0.330   small
    |delta| <  0.474   medium
    |delta| >= 0.474   large

Source: Romano, J., Kromrey, J. D., Coraggio, J., & Skowronek, J. (2006).
"Appropriate statistics for ordinal level data: Should we really be using t-test and
Cohen's d for evaluating group differences on the NSSE and other surveys?"
Annual meeting of the Florida Association of Institutional Research, February 1-3,
2006, Cocoa Beach, Florida. The cut-points are Cohen's d benchmarks (0.2, 0.5, 0.8)
converted to the dominance scale. Interval convention: lower bound inclusive, upper
bound exclusive, as written above. The convention matters at the boundaries and is
not standardised in the literature, so it is stated rather than assumed.

Limits:
  - Cliff's delta is invariant to any monotone transform of the data. That is the
    point of using it on latency, but it also means it says nothing about the size
    of a difference in milliseconds; the median difference carries that.
  - It is a dominance measure, not a location measure. Two distributions with equal
    medians but different spread can produce a non-zero delta.
  - The magnitude labels are conventions imported from social-science survey work.
    They carry no operational meaning for latency. A "negligible" delta can still be
    an unacceptable p99 regression, and a "large" delta can be irrelevant if the
    absolute difference is 40 microseconds.
  - The bootstrap CI in `cliffs_delta_ci` is NOT pre-registered and is
    supplementary. It resamples both groups independently, which assumes the
    observations within each group are exchangeable.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import mannwhitneyu

# (upper bound exclusive, label). Romano et al. (2006). See module docstring.
ROMANO_KROMREY_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (0.147, "negligible"),
    (0.330, "small"),
    (0.474, "medium"),
)
LARGEST_LABEL = "large"


def romano_kromrey_magnitude(delta: float) -> str:
    """Map |delta| to a Romano-Kromrey magnitude label."""
    magnitude = abs(float(delta))
    if not np.isfinite(magnitude):
        raise ValueError("delta must be finite")
    for bound, label in ROMANO_KROMREY_THRESHOLDS:
        if magnitude < bound:
            return label
    return LARGEST_LABEL


@dataclass
class CliffsDelta:
    delta: float
    magnitude: str
    n_x: int
    n_y: int
    ci_low: float | None = None
    ci_high: float | None = None
    ci_confidence: float | None = None

    def summary(self) -> str:
        base = (f"Cliff's delta={self.delta:+.4f} ({self.magnitude}) "
                f"n=({self.n_x}, {self.n_y})")
        if self.ci_low is not None:
            base += (f" boot-CI{self.ci_confidence:.0%}="
                     f"[{self.ci_low:+.4f}, {self.ci_high:+.4f}]")
        return base


def _delta_from_ranks(x: np.ndarray, y: np.ndarray) -> float:
    """
    delta = 2 * U_x / (n_x * n_y) - 1.

    U_x from the rank-sum identity counts each tie as one half, which is exactly the
    (#greater - #less) / (n_x n_y) definition rearranged. O(n log n) instead of the
    O(n_x n_y) double loop, which matters at 10^6 samples per group.
    """
    u = mannwhitneyu(x, y, alternative="two-sided", method="asymptotic").statistic
    return 2.0 * float(u) / (x.size * y.size) - 1.0


def cliffs_delta_bruteforce(x, y) -> float:
    """O(n_x * n_y) reference implementation. For tests and small samples only."""
    x = np.asarray(x, dtype=float).ravel()
    y = np.asarray(y, dtype=float).ravel()
    diff = x[:, None] - y[None, :]
    return float((np.count_nonzero(diff > 0) - np.count_nonzero(diff < 0))
                 / (x.size * y.size))


def cliffs_delta(x, y) -> CliffsDelta:
    """
    Cliff's delta of x relative to y, with a Romano-Kromrey magnitude label.

    Positive delta means x tends to exceed y. For latency that means x is slower.
    """
    x = np.asarray(x, dtype=float).ravel()
    y = np.asarray(y, dtype=float).ravel()
    if x.size == 0 or y.size == 0:
        raise ValueError("both samples must be non-empty")
    delta = _delta_from_ranks(x, y)
    # Guard against float drift pushing the estimate outside its support.
    delta = float(np.clip(delta, -1.0, 1.0))
    return CliffsDelta(delta=delta, magnitude=romano_kromrey_magnitude(delta),
                       n_x=int(x.size), n_y=int(y.size))


def cliffs_delta_ci(
    x,
    y,
    confidence: float = 0.95,
    n_resamples: int = 5000,
    rng=None,
) -> CliffsDelta:
    """
    Cliff's delta with a percentile bootstrap CI. NOT pre-registered, supplementary.

    Percentile rather than BCa: the jackknife influence values for a two-sample
    dominance statistic are not a leave-one-out of a single sample, so the BCa
    machinery in bca.py does not apply without modification.
    """
    x = np.asarray(x, dtype=float).ravel()
    y = np.asarray(y, dtype=float).ravel()
    base = cliffs_delta(x, y)
    rng = np.random.default_rng(rng)
    boot = np.empty(n_resamples, dtype=float)
    for b in range(n_resamples):
        xb = rng.choice(x, size=x.size, replace=True)
        yb = rng.choice(y, size=y.size, replace=True)
        boot[b] = _delta_from_ranks(xb, yb)
    alpha = 1.0 - confidence
    base.ci_low = float(np.quantile(boot, alpha / 2.0))
    base.ci_high = float(np.quantile(boot, 1.0 - alpha / 2.0))
    base.ci_confidence = confidence
    return base
