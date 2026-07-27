"""
Kruskal-Wallis, Dunn, Holm validation.

Independent references used here:
  - Kruskal-Wallis: a hand-computed H on a small tied dataset.
  - Dunn: the algebraic identity that for k = 2 groups Dunn's z is EXACTLY the
    tie-corrected Mann-Whitney normal-approximation z. scipy.stats.mannwhitneyu
    supplies the reference value, so the tie correction and the rank-sum variance
    are both checked against code this module did not write. Derivation is in the
    test docstring.
  - Holm: hand-computed adjusted p-values, including the monotonicity step.
"""

import numpy as np
import pytest
from scipy.stats import mannwhitneyu, rankdata

from pipeline import omnibus, synthetic


# ---------------------------------------------------------------------------
# Kruskal-Wallis
# ---------------------------------------------------------------------------

def test_kruskal_hand_computed_no_ties():
    """
    Groups A=[1,2,3], B=[4,5,6], C=[7,8,9]. Ranks are 1..9 in order, so
    Rbar = 2, 5, 8 and

        H = 12/(N(N+1)) * sum(n_i * Rbar_i^2) - 3(N+1)
          = 12/90 * (3*4 + 3*25 + 3*64) - 30
          = 0.133333 * 279 - 30 = 37.2 - 30 = 7.2
    """
    res = omnibus.kruskal_wallis([[1, 2, 3], [4, 5, 6], [7, 8, 9]],
                                 labels=["A", "B", "C"])
    assert res.statistic == pytest.approx(7.2, rel=1e-12)
    assert res.df == 2
    assert res.group_sizes == {"A": 3, "B": 3, "C": 3}


def test_kruskal_hand_computed_with_ties():
    """
    A=[1,1,2], B=[2,3,3]. N=6. Midranks: value 1 -> 1.5, 1.5; value 2 -> 3.5, 3.5;
    value 3 -> 5.5, 5.5. R_A = 1.5+1.5+3.5 = 6.5, R_B = 3.5+5.5+5.5 = 14.5.
    Rbar_A = 2.16667, Rbar_B = 4.83333.

        H_uncorrected = 12/42 * (3*2.16667^2 + 3*4.83333^2) - 21
                      = 0.285714 * (14.0833 + 70.0833) - 21 = 24.0476 - 21 = 3.04762
        tie factor    = 1 - sum(t^3 - t)/(N^3 - N) = 1 - (6+6+6)/210 = 1 - 0.0857143
        H             = 3.04762 / 0.914286 = 3.33333
    """
    res = omnibus.kruskal_wallis([[1, 1, 2], [2, 3, 3]])
    assert res.statistic == pytest.approx(3.3333333333, rel=1e-9)


def test_kruskal_identical_groups_not_significant():
    rng = np.random.default_rng(4)
    groups = {f"g{i}": rng.normal(10.0, 1.0, size=60) for i in range(4)}
    res = omnibus.kruskal_wallis(groups)
    assert not res.significant, res.summary()


def test_kruskal_separated_groups_significant():
    rng = np.random.default_rng(5)
    groups = {
        "low": rng.normal(10.0, 1.0, size=60),
        "mid": rng.normal(12.0, 1.0, size=60),
        "high": rng.normal(14.0, 1.0, size=60),
    }
    res = omnibus.kruskal_wallis(groups)
    assert res.significant and res.pvalue < 1e-10, res.summary()


# ---------------------------------------------------------------------------
# Holm
# ---------------------------------------------------------------------------

def test_holm_hand_computed():
    """
    p = [0.010, 0.020, 0.030, 0.040], m = 4.
    Step-down multipliers 4, 3, 2, 1:
      0.010*4 = 0.040
      0.020*3 = 0.060
      0.030*2 = 0.060  -> running max keeps 0.060
      0.040*1 = 0.040  -> running max lifts it to 0.060
    """
    got = omnibus.holm_adjust([0.010, 0.020, 0.030, 0.040])
    assert got == pytest.approx([0.040, 0.060, 0.060, 0.060])


def test_holm_preserves_input_order():
    got = omnibus.holm_adjust([0.040, 0.010, 0.030, 0.020])
    assert got == pytest.approx([0.060, 0.040, 0.060, 0.060])


def test_holm_clips_at_one():
    got = omnibus.holm_adjust([0.4, 0.5, 0.6])
    assert got == pytest.approx([1.0, 1.0, 1.0])


def test_holm_single_pvalue_is_unchanged():
    assert omnibus.holm_adjust([0.023]) == pytest.approx([0.023])


def test_holm_is_monotone_and_at_least_raw():
    rng = np.random.default_rng(8)
    p = rng.uniform(0, 1, size=25)
    adj = omnibus.holm_adjust(p)
    assert np.all(adj >= p - 1e-15)
    order = np.argsort(p)
    assert np.all(np.diff(adj[order]) >= -1e-15)


def test_holm_rejects_bad_input():
    with pytest.raises(ValueError):
        omnibus.holm_adjust([0.1, 1.4])
    with pytest.raises(ValueError):
        omnibus.holm_adjust([0.1, np.nan])


# ---------------------------------------------------------------------------
# Dunn
# ---------------------------------------------------------------------------

def _mannwhitney_z(x, y):
    """Tie-corrected Mann-Whitney normal-approximation z, from scipy's U."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    n1, n2 = x.size, y.size
    n = n1 + n2
    u = mannwhitneyu(x, y, alternative="two-sided",
                     method="asymptotic", use_continuity=False).statistic
    pooled = np.concatenate([x, y])
    _, counts = np.unique(pooled, return_counts=True)
    tie_term = np.sum(counts.astype(float) ** 3 - counts) / (n * (n - 1))
    sigma = np.sqrt(n1 * n2 / 12.0 * ((n + 1) - tie_term))
    return (u - n1 * n2 / 2.0) / sigma


@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_dunn_two_groups_equals_mannwhitney_z(seed):
    """
    INDEPENDENT REFERENCE CHECK.

    For k = 2, write D = Rbar_1 - Rbar_2. Using R_1 + R_2 = N(N+1)/2,

        D = R_1(1/n1 + 1/n2) - N(N+1)/(2 n2) = (N/(n1 n2)) * (R_1 - E[R_1])

    and R_1 - E[R_1] = U_1 - E[U_1] because U_1 = R_1 - n1(n1+1)/2 is a constant
    shift. Dunn's denominator is sqrt((A - T) * N/(n1 n2)) with A = N(N+1)/12 and
    T = sum(t^3 - t)/(12(N-1)), so

        z_dunn = (U_1 - E[U_1]) / sqrt((n1 n2 / N) * (A - T))

    and (n1 n2 / N)(A - T) = (n1 n2 / 12)[(N+1) - sum(t^3-t)/(N(N-1))], which is
    exactly the tie-corrected Mann-Whitney variance of U. So the two z values must
    agree to machine precision. scipy computes U and this test computes the variance
    from the textbook formula, neither via pipeline.omnibus.
    """
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 12, size=25).astype(float)  # small range forces ties
    y = rng.integers(2, 15, size=31).astype(float)
    res = omnibus.dunn_posthoc({"x": x, "y": y})
    assert len(res.pairs) == 1
    assert res.pairs[0].z == pytest.approx(_mannwhitney_z(x, y), rel=1e-10)


def test_dunn_two_groups_no_ties_equals_mannwhitney_z():
    rng = np.random.default_rng(77)
    x = rng.normal(0, 1, size=20)
    y = rng.normal(0.8, 1, size=24)
    res = omnibus.dunn_posthoc({"x": x, "y": y})
    assert res.pairs[0].z == pytest.approx(_mannwhitney_z(x, y), rel=1e-10)
    assert res.tie_correction == 0.0


def test_dunn_z_hand_computed_three_groups():
    """
    A=[1,2,3], B=[4,5,6], C=[7,8,9]. N=9, no ties.
    Rbar = 2, 5, 8. A_term = 9*10/12 = 7.5, T = 0.
    SE for equal n=3: sqrt(7.5 * (1/3 + 1/3)) = sqrt(5) = 2.2360679...
    z(A,B) = (2 - 5)/sqrt(5) = -1.3416408
    z(A,C) = (2 - 8)/sqrt(5) = -2.6832816
    z(B,C) = (5 - 8)/sqrt(5) = -1.3416408
    """
    res = omnibus.dunn_posthoc([[1, 2, 3], [4, 5, 6], [7, 8, 9]],
                               labels=["A", "B", "C"])
    by_pair = {(p.a, p.b): p.z for p in res.pairs}
    root5 = np.sqrt(5.0)
    assert by_pair[("A", "B")] == pytest.approx(-3.0 / root5, rel=1e-12)
    assert by_pair[("A", "C")] == pytest.approx(-6.0 / root5, rel=1e-12)
    assert by_pair[("B", "C")] == pytest.approx(-3.0 / root5, rel=1e-12)


def test_dunn_uses_pooled_ranks_not_pairwise_ranks():
    """
    Pooled ranking is what distinguishes Dunn from repeated Mann-Whitney. Adding a
    third, far-away group must change the A-vs-B z, because it changes N and the
    pooled ranks. If this ever stops being true, the implementation has silently
    become pairwise.
    """
    a = [1.0, 2.0, 3.0, 4.0, 5.0]
    b = [2.5, 3.5, 4.5, 5.5, 6.5]
    two = omnibus.dunn_posthoc({"A": a, "B": b}).pairs[0].z
    three = next(p.z for p in omnibus.dunn_posthoc(
        {"A": a, "B": b, "C": [100.0, 101.0, 102.0, 103.0, 104.0]}).pairs
        if (p.a, p.b) == ("A", "B"))
    assert two != pytest.approx(three)


def test_dunn_identical_groups_not_significant():
    """Four draws from one distribution must produce no significant pair."""
    rng = np.random.default_rng(2024)
    groups = {f"g{i}": rng.normal(10.0, 1.0, size=80) for i in range(4)}
    res = omnibus.dunn_posthoc(groups)
    assert not any(p.significant for p in res.pairs), res.summary()


def test_dunn_separated_groups_are_significant_in_the_right_direction():
    rng = np.random.default_rng(2025)
    groups = {
        "fast": rng.normal(10.0, 0.5, size=80),
        "slow": rng.normal(14.0, 0.5, size=80),
    }
    res = omnibus.dunn_posthoc(groups)
    pair = res.pairs[0]
    assert pair.significant
    assert pair.z < 0  # 'fast' has the lower mean rank


def test_dunn_holm_is_applied():
    """The adjusted p must equal Holm of the raw p vector, not the raw p."""
    rng = np.random.default_rng(31)
    groups = {"a": rng.normal(0, 1, 40), "b": rng.normal(0.5, 1, 40),
              "c": rng.normal(1.0, 1, 40), "d": rng.normal(1.5, 1, 40)}
    res = omnibus.dunn_posthoc(groups)
    raw = [p.p_raw for p in res.pairs]
    expected = omnibus.holm_adjust(raw)
    assert [p.p_adjusted for p in res.pairs] == pytest.approx(list(expected))
    assert res.n_comparisons == 6


def test_dunn_warns_on_small_groups():
    res = omnibus.dunn_posthoc([[1, 2, 3], [4, 5, 6]])
    assert any("normal approximation" in w for w in res.warnings)


def test_dunn_rejects_all_tied_input():
    with pytest.raises(ValueError):
        omnibus.dunn_posthoc([[5.0] * 10, [5.0] * 10])


def test_tie_correction_matches_rankdata_midranks():
    """Cross-check the tie bookkeeping against scipy's midranks directly."""
    x = np.array([1.0, 1.0, 2.0, 2.0, 2.0, 3.0])
    ranks = rankdata(x)
    assert list(ranks) == pytest.approx([1.5, 1.5, 4.0, 4.0, 4.0, 6.0])
    res = omnibus.dunn_posthoc([x[:3], x[3:]])
    # sum(t^3 - t) = (8-2) + (27-3) = 30; N = 6; T = 30 / (12*5) = 0.5
    assert res.tie_correction == pytest.approx(0.5)


def test_end_to_end_on_synthetic_conditions():
    groups = synthetic.synthetic_condition_set(n_replications=30, rng=1234)
    kw = omnibus.kruskal_wallis(groups)
    assert kw.significant
    dunn = omnibus.dunn_posthoc(groups)
    pair = next(p for p in dunn.pairs if {p.a, p.b} == {"D1", "D2"})
    assert pair.significant and pair.z < 0  # D2 was generated slower than D1
