"""
Kruskal-Wallis omnibus test, Dunn post-hoc pairwise tests, Holm correction.

Pre-registered (PREREGISTRATION.md): "Kruskal-Wallis omnibus comparison, followed
by Dunn post-hoc pairwise tests with Holm correction."

Kruskal-Wallis comes from scipy (tie-corrected). Dunn and Holm are hand-rolled
because neither scipy nor the standard library provides them; both are validated in
tests/test_omnibus.py against independent references, see the notes there.

Dunn (1964), "Multiple comparisons using rank sums", Technometrics 6(3): 241-252.
The test statistic for the pair (i, j), on ranks pooled across ALL k groups:

    z_ij = (Rbar_i - Rbar_j) / sqrt( (A - T) * (1/n_i + 1/n_j) )
    A    = N(N+1)/12
    T    = sum_over_tied_groups(t^3 - t) / (12(N-1))

with two-sided p from the standard normal. Pooling the ranks across all groups is
what makes this a post-hoc for Kruskal-Wallis rather than a series of pairwise
Mann-Whitney tests: the ranks are not recomputed per pair, so the comparisons stay
on the same scale as the omnibus.

Holm (1979), "A simple sequentially rejective multiple test procedure", Scandinavian
Journal of Statistics 6(2): 65-70. Step-down, with the usual monotonicity
enforcement so adjusted p-values are non-decreasing in the sorted raw p-values.

Assumptions and limits:
  - Kruskal-Wallis tests stochastic dominance, not equality of medians. It is only a
    median test under the additional assumption that the group distributions have
    the same shape and scale. Latency distributions under different conditions
    generally do NOT have the same shape, so a significant H means "at least one
    condition stochastically dominates another", not "the medians differ".
  - Dunn's z uses the normal approximation. It is unreliable for very small groups
    (rule of thumb n_i >= 5 per group). `warnings` flags that.
  - Holm controls the family-wise error rate across the pairs passed in one call.
    Running this function separately per load level and then reporting all pairs
    together silently inflates the family; the family is fixed before the run.
  - PREREGISTRATION.md does not state whether the omnibus operates on per-
    replication p99 values or on pooled per-request latencies. These are different
    tests with different n and different independence structure. This module is
    agnostic; the caller must fix that choice and record it. See README.md,
    "Open specification gaps".
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from scipy.stats import kruskal as _scipy_kruskal
from scipy.stats import norm, rankdata

MIN_GROUP_SIZE_FOR_NORMAL_APPROX = 5


@dataclass
class KruskalResult:
    statistic: float
    pvalue: float
    df: int
    group_sizes: dict[str, int]
    alpha: float = 0.05

    @property
    def significant(self) -> bool:
        return self.pvalue < self.alpha

    def summary(self) -> str:
        return (
            f"Kruskal-Wallis H={self.statistic:.5g} df={self.df} "
            f"p={self.pvalue:.4g} "
            f"{'reject' if self.significant else 'fail to reject'} H0 "
            f"at alpha={self.alpha:g}"
        )


@dataclass
class PairwiseResult:
    a: str
    b: str
    z: float
    p_raw: float
    p_adjusted: float
    mean_rank_a: float
    mean_rank_b: float
    significant: bool

    def summary(self) -> str:
        return (
            f"{self.a} vs {self.b}: z={self.z:+.4g} p={self.p_raw:.4g} "
            f"p_holm={self.p_adjusted:.4g} "
            f"{'significant' if self.significant else 'n.s.'}"
        )


@dataclass
class DunnResult:
    pairs: list[PairwiseResult]
    alpha: float
    n_comparisons: int
    tie_correction: float
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        head = (f"Dunn post-hoc, Holm-corrected, {self.n_comparisons} comparisons, "
                f"alpha={self.alpha:g}")
        return "\n".join([head] + ["  " + p.summary() for p in self.pairs])


def _as_named_groups(groups, labels):
    if isinstance(groups, dict):
        if labels is not None:
            raise ValueError("pass either a dict or (groups, labels), not both")
        items = list(groups.items())
    else:
        groups = list(groups)
        if labels is None:
            labels = [f"g{i}" for i in range(len(groups))]
        if len(labels) != len(groups):
            raise ValueError("labels and groups length mismatch")
        items = list(zip(labels, groups))
    named = [(str(name), np.asarray(v, dtype=float).ravel()) for name, v in items]
    if len(named) < 2:
        raise ValueError("need at least 2 groups")
    for name, v in named:
        if v.size == 0:
            raise ValueError(f"group {name!r} is empty")
    return named


def kruskal_wallis(groups, labels=None, alpha: float = 0.05) -> KruskalResult:
    """Tie-corrected Kruskal-Wallis omnibus test. Thin wrapper over scipy."""
    named = _as_named_groups(groups, labels)
    stat, p = _scipy_kruskal(*[v for _, v in named])
    return KruskalResult(
        statistic=float(stat),
        pvalue=float(p),
        df=len(named) - 1,
        group_sizes={name: int(v.size) for name, v in named},
        alpha=alpha,
    )


def holm_adjust(pvalues) -> np.ndarray:
    """
    Holm-Bonferroni step-down adjusted p-values.

    p_adj_(i) = max_{j <= i} min(1, (m - j) * p_(j)) over ascending-sorted p, then
    mapped back to the input order. The running maximum is what makes the adjusted
    values monotone; without it a small p later in the sequence could be reported as
    more significant than a smaller p earlier in it.
    """
    p = np.asarray(pvalues, dtype=float).ravel()
    if p.size == 0:
        return p
    if np.any((p < 0) | (p > 1)) or np.any(np.isnan(p)):
        raise ValueError("p-values must be in [0, 1] and non-NaN")
    m = p.size
    order = np.argsort(p, kind="stable")
    scaled = (m - np.arange(m)) * p[order]
    adjusted_sorted = np.maximum.accumulate(scaled)
    out = np.empty(m, dtype=float)
    out[order] = np.clip(adjusted_sorted, 0.0, 1.0)
    return out


def dunn_posthoc(groups, labels=None, alpha: float = 0.05) -> DunnResult:
    """
    Dunn's post-hoc pairwise test on pooled ranks, with Holm correction.

    Returns every unordered pair. z is signed: positive means group `a` has the
    higher mean rank, i.e. `a` is stochastically larger (slower, for latency).
    """
    named = _as_named_groups(groups, labels)
    names = [n for n, _ in named]
    sizes = np.array([v.size for _, v in named], dtype=float)

    pooled = np.concatenate([v for _, v in named])
    n_total = pooled.size
    ranks = rankdata(pooled)

    _, tie_counts = np.unique(pooled, return_counts=True)
    tie_sum = float(np.sum(tie_counts.astype(float) ** 3 - tie_counts))
    variance_base = n_total * (n_total + 1) / 12.0
    tie_correction = tie_sum / (12.0 * (n_total - 1)) if n_total > 1 else 0.0
    sigma_sq_base = variance_base - tie_correction

    warnings: list[str] = []
    if sigma_sq_base <= 0:
        raise ValueError(
            "rank variance is non-positive after tie correction; "
            "the pooled sample is (almost) entirely tied"
        )
    if sizes.min() < MIN_GROUP_SIZE_FOR_NORMAL_APPROX:
        warnings.append(
            f"smallest group has n={int(sizes.min())}; Dunn's normal approximation "
            f"is unreliable below n={MIN_GROUP_SIZE_FOR_NORMAL_APPROX}"
        )
    if tie_sum > 0:
        tied_fraction = 1.0 - len(tie_counts) / n_total
        warnings.append(f"ties present: {tied_fraction:.1%} of observations are "
                        f"not unique; tie correction applied")

    offsets = np.concatenate([[0], np.cumsum(sizes).astype(int)])
    mean_ranks = np.array([
        ranks[offsets[i]:offsets[i + 1]].mean() for i in range(len(named))
    ])

    raw = []
    meta = []
    for i in range(len(named)):
        for j in range(i + 1, len(named)):
            se = np.sqrt(sigma_sq_base * (1.0 / sizes[i] + 1.0 / sizes[j]))
            z = (mean_ranks[i] - mean_ranks[j]) / se
            p = 2.0 * norm.sf(abs(z))
            raw.append(p)
            meta.append((i, j, float(z), float(p)))

    adjusted = holm_adjust(raw)
    pairs = [
        PairwiseResult(
            a=names[i], b=names[j], z=z, p_raw=p,
            p_adjusted=float(adj),
            mean_rank_a=float(mean_ranks[i]), mean_rank_b=float(mean_ranks[j]),
            significant=bool(adj < alpha),
        )
        for (i, j, z, p), adj in zip(meta, adjusted)
    ]
    return DunnResult(pairs=pairs, alpha=alpha, n_comparisons=len(pairs),
                      tie_correction=tie_correction, warnings=warnings)
