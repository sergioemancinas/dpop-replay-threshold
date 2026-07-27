"""
Cliff's delta and Romano-Kromrey thresholds validation.

Independent references used here:
  - An O(n_x * n_y) brute-force count of (#greater - #less), written directly from
    the Cliff (1993) definition, checked against the O(n log n) rank-based path.
  - scipy.stats.mannwhitneyu's U, via delta = 2U/(n_x n_y) - 1, which is a second
    independent route to the same number.
  - Hand-computed deltas on tiny samples where the count is checkable by eye.
"""

import numpy as np
import pytest
from scipy.stats import mannwhitneyu

from pipeline import effect_size


def test_hand_computed_complete_dominance():
    """Every x beats every y: 9 greater, 0 less, delta = 9/9 = 1."""
    d = effect_size.cliffs_delta([4, 5, 6], [1, 2, 3])
    assert d.delta == pytest.approx(1.0)
    assert d.magnitude == "large"


def test_hand_computed_complete_subordination():
    d = effect_size.cliffs_delta([1, 2, 3], [4, 5, 6])
    assert d.delta == pytest.approx(-1.0)
    assert d.magnitude == "large"


def test_hand_computed_all_ties():
    """All pairs tied: 0 greater, 0 less, delta = 0."""
    d = effect_size.cliffs_delta([2, 2, 2], [2, 2, 2])
    assert d.delta == pytest.approx(0.0)
    assert d.magnitude == "negligible"


def test_hand_computed_mixed():
    """
    x = [1, 3], y = [2, 2]. Pairs: (1,2) less, (1,2) less, (3,2) greater,
    (3,2) greater. delta = (2 - 2)/4 = 0.
    """
    assert effect_size.cliffs_delta([1, 3], [2, 2]).delta == pytest.approx(0.0)


def test_hand_computed_partial_with_tie():
    """
    x = [1, 2, 3], y = [2, 4].
    (1,2)<  (1,4)<  (2,2)=  (2,4)<  (3,2)>  (3,4)<
    greater = 1, less = 4, ties = 1. delta = (1 - 4)/6 = -0.5.
    """
    assert effect_size.cliffs_delta([1, 2, 3], [2, 4]).delta == pytest.approx(-0.5)


@pytest.mark.parametrize("seed", range(6))
def test_rank_path_matches_bruteforce(seed):
    """Rank-based fast path against the definitional double loop, with ties."""
    rng = np.random.default_rng(seed)
    x = rng.integers(0, 8, size=40).astype(float)
    y = rng.integers(1, 10, size=53).astype(float)
    assert effect_size.cliffs_delta(x, y).delta == pytest.approx(
        effect_size.cliffs_delta_bruteforce(x, y), abs=1e-12)


def test_matches_mannwhitney_identity():
    """delta = 2U/(n_x n_y) - 1, computed here straight from scipy's U."""
    rng = np.random.default_rng(99)
    x = rng.normal(0.0, 1.0, size=70)
    y = rng.normal(0.6, 1.3, size=90)
    u = mannwhitneyu(x, y, alternative="two-sided").statistic
    expected = 2.0 * u / (x.size * y.size) - 1.0
    assert effect_size.cliffs_delta(x, y).delta == pytest.approx(expected, rel=1e-12)


def test_antisymmetry():
    rng = np.random.default_rng(3)
    x, y = rng.normal(size=30), rng.normal(1, 1, size=25)
    assert (effect_size.cliffs_delta(x, y).delta
            == pytest.approx(-effect_size.cliffs_delta(y, x).delta))


def test_invariant_under_monotone_transform():
    """Cliff's delta is ordinal, so log() must not move it."""
    rng = np.random.default_rng(12)
    x = rng.lognormal(1.0, 0.5, size=60)
    y = rng.lognormal(1.4, 0.5, size=60)
    assert (effect_size.cliffs_delta(x, y).delta
            == pytest.approx(effect_size.cliffs_delta(np.log(x), np.log(y)).delta))


def test_identical_distributions_give_near_zero_delta():
    rng = np.random.default_rng(21)
    x, y = rng.normal(10, 1, size=4000), rng.normal(10, 1, size=4000)
    d = effect_size.cliffs_delta(x, y)
    assert abs(d.delta) < 0.05
    assert d.magnitude == "negligible"


def test_romano_kromrey_boundaries_exact():
    """
    Cut-points 0.147 / 0.330 / 0.474, lower bound inclusive, upper exclusive.
    Boundary values themselves belong to the HIGHER band.
    """
    f = effect_size.romano_kromrey_magnitude
    assert f(0.0) == "negligible"
    assert f(0.1469999) == "negligible"
    assert f(0.147) == "small"
    assert f(0.3299999) == "small"
    assert f(0.330) == "medium"
    assert f(0.4739999) == "medium"
    assert f(0.474) == "large"
    assert f(1.0) == "large"


def test_romano_kromrey_uses_absolute_value():
    f = effect_size.romano_kromrey_magnitude
    assert f(-0.5) == f(0.5) == "large"
    assert f(-0.2) == f(0.2) == "small"


def test_known_separation_lands_in_expected_band():
    """
    For two normals differing by delta_mu with common sigma, the dominance
    probability is P(X > Y) = Phi(delta_mu / (sigma * sqrt(2))), and Cliff's delta
    is 2P - 1. With delta_mu = 1 and sigma = 1: Phi(0.7071) = 0.76025, so the
    expected delta is 0.5205, which is 'large'.
    """
    from scipy.stats import norm
    expected = 2 * norm.cdf(1.0 / np.sqrt(2.0)) - 1
    assert expected == pytest.approx(0.52050, abs=1e-4)

    rng = np.random.default_rng(64)
    x = rng.normal(1.0, 1.0, size=20000)
    y = rng.normal(0.0, 1.0, size=20000)
    d = effect_size.cliffs_delta(x, y)
    assert d.delta == pytest.approx(expected, abs=0.02)
    assert d.magnitude == "large"


def test_small_separation_lands_in_small_band():
    """delta_mu = 0.3, sigma = 1 -> 2*Phi(0.2121) - 1 = 0.1680, 'small'."""
    from scipy.stats import norm
    expected = 2 * norm.cdf(0.3 / np.sqrt(2.0)) - 1
    assert expected == pytest.approx(0.16800, abs=1e-4)

    rng = np.random.default_rng(65)
    x = rng.normal(0.3, 1.0, size=40000)
    y = rng.normal(0.0, 1.0, size=40000)
    d = effect_size.cliffs_delta(x, y)
    assert d.delta == pytest.approx(expected, abs=0.02)
    assert d.magnitude == "small"


def test_bootstrap_ci_brackets_point_and_covers_zero_for_identical():
    rng = np.random.default_rng(7)
    x, y = rng.normal(size=200), rng.normal(size=200)
    d = effect_size.cliffs_delta_ci(x, y, n_resamples=400, rng=rng)
    assert d.ci_low <= d.delta <= d.ci_high
    assert d.ci_low < 0 < d.ci_high


def test_bootstrap_ci_excludes_zero_for_separated():
    rng = np.random.default_rng(8)
    x, y = rng.normal(2.0, 1.0, size=200), rng.normal(0.0, 1.0, size=200)
    d = effect_size.cliffs_delta_ci(x, y, n_resamples=400, rng=rng)
    assert d.ci_low > 0


def test_rejects_empty_sample():
    with pytest.raises(ValueError):
        effect_size.cliffs_delta([], [1, 2, 3])
