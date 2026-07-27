"""
BCa validation.

Independent references used here:
  - scipy.stats.bootstrap(method='BCa') for the interval itself.
  - A closed-form acceleration for the mean, derived by hand (see the test), which
    checks the jackknife code path without going through scipy.
  - Monte Carlo coverage against a known population median.
"""

import numpy as np
import pytest
from scipy.stats import bootstrap as scipy_bootstrap

from pipeline import bca


def _mean_stat(a, axis=-1):
    return np.mean(a, axis=axis)


def test_acceleration_for_mean_matches_closed_form():
    """
    For statistic = mean, the jackknife influence values are u_i = (x_i - xbar)/(n-1),
    so Efron's

        a = sum(u^3) / (6 * (sum(u^2))^{3/2})

    collapses to a form with no (n-1) factors at all:

        a = sum(d^3) / (6 * (sum(d^2))^{3/2}),   d_i = x_i - xbar

    This is an algebraic identity, computed here without reference to the
    implementation, so it validates the jackknife code independently.
    """
    rng = np.random.default_rng(20260727)
    x = rng.lognormal(0.0, 0.6, size=37)
    d = x - x.mean()
    expected = (d ** 3).sum() / (6.0 * ((d ** 2).sum()) ** 1.5)
    got = bca._jackknife_acceleration(x, _mean_stat)
    assert got == pytest.approx(expected, rel=1e-12)


def test_acceleration_zero_for_symmetric_sample():
    """A sample symmetric about its mean has zero third central moment, so a = 0."""
    x = np.array([-3.0, -1.0, 0.0, 1.0, 3.0])
    assert bca._jackknife_acceleration(x, _mean_stat) == pytest.approx(0.0, abs=1e-15)


def test_bca_mean_agrees_with_scipy_bootstrap():
    """
    Cross-check against scipy's BCa on the mean, a smooth statistic where both
    implementations should land in the same place up to Monte Carlo noise.
    Resampling schemes differ, so agreement is asserted relative to the interval
    width, not to machine precision.
    """
    rng = np.random.default_rng(11)
    x = rng.lognormal(1.0, 0.4, size=60)

    mine = bca.bca_ci(x, _mean_stat, confidence=0.95, n_resamples=40000,
                      rng=np.random.default_rng(1))
    theirs = scipy_bootstrap((x,), np.mean, confidence_level=0.95,
                             n_resamples=40000, method="BCa",
                             random_state=np.random.default_rng(2))
    width = theirs.confidence_interval.high - theirs.confidence_interval.low
    assert abs(mine.low - theirs.confidence_interval.low) < 0.03 * width
    assert abs(mine.high - theirs.confidence_interval.high) < 0.03 * width


def test_bca_median_agrees_with_scipy_bootstrap():
    """
    Same cross-check for the median, the statistic the pre-registration actually
    uses. The tolerance is looser because the bootstrap distribution of the median
    is lattice-valued, so both implementations snap their endpoints to observed
    order statistics.
    """
    rng = np.random.default_rng(303)
    x = rng.lognormal(2.0, 0.3, size=80)

    mine = bca.bca_ci(x, bca.median_statistic, n_resamples=40000,
                      rng=np.random.default_rng(5))
    theirs = scipy_bootstrap((x,), np.median, confidence_level=0.95,
                             n_resamples=40000, method="BCa",
                             random_state=np.random.default_rng(6))
    width = theirs.confidence_interval.high - theirs.confidence_interval.low
    assert abs(mine.low - theirs.confidence_interval.low) < 0.10 * width
    assert abs(mine.high - theirs.confidence_interval.high) < 0.10 * width


def test_bca_covers_known_population_median():
    """
    Monte Carlo coverage. The population is lognormal(mu=1, sigma=0.5), whose median
    is exp(1) exactly. Nominal coverage is 95%; BCa on the median with n=40 is not
    exact, so the band is generous but still falsifiable.
    """
    true_median = np.exp(1.0)
    rng = np.random.default_rng(4242)
    hits = 0
    trials = 300
    for _ in range(trials):
        x = rng.lognormal(1.0, 0.5, size=40)
        ci = bca.bca_ci(x, bca.median_statistic, n_resamples=1200, rng=rng)
        hits += ci.low <= true_median <= ci.high
    coverage = hits / trials
    assert 0.88 <= coverage <= 0.995, f"coverage {coverage:.3f} out of band"


def test_degenerate_sample_flags_and_falls_back():
    x = np.full(20, 7.5)
    res = bca.bca_ci(x, bca.median_statistic, n_resamples=500, rng=1)
    assert res.degenerate
    assert res.low == res.high == 7.5
    assert any("percentile" in w for w in res.warnings)


def test_small_n_warns():
    res = bca.bca_ci([1.0, 2.0, 3.0, 4.0, 5.0], n_resamples=500, rng=0)
    assert any("BCa acceleration is unreliable" in w for w in res.warnings)


def test_relative_half_width_and_target():
    res = bca.BcaResult(point=100.0, low=97.0, high=104.0, confidence=0.95,
                        n=10, n_resamples=1000, z0=0.0, acceleration=0.0)
    assert res.half_width == pytest.approx(4.0)          # max arm, not the average
    assert res.relative_half_width == pytest.approx(0.04)
    assert res.meets_target


def test_replication_rule_hand_computed():
    """
    n_req = ceil(n * (rel/target)^2). With n=12, rel=0.12, target=0.05:
    12 * (0.12/0.05)^2 = 12 * 5.76 = 69.12 -> 70.
    """
    res = bca.BcaResult(point=100.0, low=88.0, high=112.0, confidence=0.95,
                        n=12, n_resamples=1000, z0=0.0, acceleration=0.0)
    assert res.relative_half_width == pytest.approx(0.12)
    assert bca.replications_for_target_width(res, 0.05) == 70


def test_replication_rule_returns_pilot_n_when_already_met():
    res = bca.BcaResult(point=100.0, low=98.0, high=102.0, confidence=0.95,
                        n=25, n_resamples=1000, z0=0.0, acceleration=0.0)
    assert bca.replications_for_target_width(res, 0.05) == 25


def test_empirical_replication_curve_matches_asymptotic_median_se():
    """
    Independently computed expected value.

    For a normal population the asymptotic standard error of the sample median is
    sqrt(pi/2) * sigma / sqrt(n) = 1.2533 * sigma / sqrt(n). A 95% interval has
    half-width 1.96 * SE, so the n at which the RELATIVE half-width first reaches
    5% of the median mu solves

        1.96 * 1.2533 * sigma / sqrt(n) = 0.05 * mu
        n = (1.96 * 1.2533 * sigma / (0.05 * mu))^2

    With mu=100, sigma=10 that is (2.4565 * 10 / 5)^2 = 24.13, so n = 25.
    The nested-bootstrap curve is a finite-sample, non-normal-theory procedure, so
    it is only required to land within a factor of two of that.
    """
    mu, sigma = 100.0, 10.0
    analytic_n = (1.959964 * np.sqrt(np.pi / 2) * sigma / (0.05 * mu)) ** 2
    assert analytic_n == pytest.approx(24.13, abs=0.05)

    rng = np.random.default_rng(777)
    pilot = rng.normal(mu, sigma, size=4000)  # large pilot: the ECDF is ~ the truth
    curve, chosen = bca.empirical_replication_curve(
        pilot, candidate_ns=[10, 15, 20, 25, 30, 40, 60, 90],
        target=0.05, n_trials=30, n_resamples=800, rng=rng)

    assert chosen is not None, [(p.n, p.median_relative_half_width) for p in curve]
    assert 0.5 * analytic_n <= chosen <= 2.0 * analytic_n, (
        f"chosen n={chosen}, analytic n={analytic_n:.1f}")
    widths = [p.median_relative_half_width for p in curve]
    assert widths == sorted(widths, reverse=True), "half-width must shrink with n"


def test_smallest_n_with_confidence_is_stricter_than_the_median_rule():
    """
    The median criterion accepts an n at which only about half of pilots would
    actually hit the target. Requiring 80% must never pick a smaller n.
    """
    rng = np.random.default_rng(777)
    pilot = rng.normal(100.0, 10.0, size=4000)
    curve, median_choice = bca.empirical_replication_curve(
        pilot, candidate_ns=[10, 20, 30, 40, 60, 90, 140],
        target=0.05, n_trials=30, n_resamples=800, rng=rng)
    strict = bca.smallest_n_with_confidence(curve, 0.80)
    assert strict is not None and median_choice is not None
    assert strict >= median_choice
    chosen_point = next(p for p in curve if p.n == median_choice)
    assert chosen_point.fraction_meeting_target < 0.80, (
        "expected the median rule to accept a coin-flip n on this pilot")


def test_smallest_n_with_confidence_rejects_bad_fraction():
    with pytest.raises(ValueError):
        bca.smallest_n_with_confidence([], 0.0)


def test_bca_rejects_tiny_sample():
    with pytest.raises(ValueError):
        bca.bca_ci([1.0])
