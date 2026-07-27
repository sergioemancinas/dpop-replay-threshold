"""
Split-half KS validation.

Cases with known answers: an iid window (must NOT reject), a drifting window (must
reject), a hand-computed KS statistic on tiny samples, and a measurement of the
type-I error inflation under autocorrelation, which documents the main limitation
rather than hiding it.
"""

import numpy as np
import pytest

from pipeline import stationarity, synthetic


def test_hand_computed_ks_statistic():
    """
    first  = [1, 2, 3, 4]      second = [5, 6, 7, 8]
    The empirical CDFs are disjoint, so the maximum vertical gap is 1.0 and D = 1.

    The exact two-sided p-value is combinatorial: of the C(8,4) = 70 equally likely
    interleavings under H0, exactly 2 are fully separated, so p = 2/70.
    """
    res = stationarity.split_half_ks([1, 2, 3, 4, 5, 6, 7, 8])
    assert res.statistic == pytest.approx(1.0)
    assert res.n_first == 4 and res.n_second == 4
    assert res.pvalue == pytest.approx(2.0 / 70.0, rel=1e-9)
    assert res.rejects_stationarity is True


def test_hand_computed_partial_overlap():
    """
    first = [1, 2, 5, 6], second = [3, 4, 7, 8].
    Step through the pooled order 1..8 tracking F1 - F2 in quarters:
      1: .25-0=.25   2: .50-0=.50   3: .50-.25=.25   4: .50-.50=0
      5: .75-.50=.25 6: 1.0-.50=.50 7: 1.0-.75=.25   8: 0
    Maximum absolute gap is 0.50.
    """
    res = stationarity.split_half_ks([1, 2, 5, 6, 3, 4, 7, 8])
    assert res.statistic == pytest.approx(0.5)


def test_iid_window_is_not_flagged():
    rng = np.random.default_rng(9001)
    x = synthetic.synthetic_stationary_window(20000, rng=rng)
    res = stationarity.split_half_ks(x)
    assert not res.rejects_stationarity, res.summary()


def test_identical_halves_give_p_one():
    """Two identical halves are the strongest possible non-rejection."""
    half = np.arange(1, 501, dtype=float)
    res = stationarity.split_half_ks(np.concatenate([half, half]))
    assert res.statistic == pytest.approx(0.0)
    assert res.pvalue == pytest.approx(1.0)


def test_drifting_window_is_flagged():
    rng = np.random.default_rng(9002)
    x = synthetic.synthetic_nonstationary_window(20000, drift=0.5, rng=rng)
    res = stationarity.split_half_ks(x)
    assert res.rejects_stationarity, res.summary()
    assert res.pvalue < 1e-6
    assert res.median_second > res.median_first


def test_step_change_at_midpoint_is_flagged():
    rng = np.random.default_rng(9003)
    a = rng.normal(10.0, 1.0, size=5000)
    b = rng.normal(10.5, 1.0, size=5000)
    res = stationarity.split_half_ks(np.concatenate([a, b]))
    assert res.rejects_stationarity
    assert res.statistic > res.min_detectable_shift


def test_iid_false_positive_rate_is_near_nominal():
    """Sanity: with independent data the test rejects at roughly alpha."""
    rng = np.random.default_rng(555)
    rejects = sum(
        stationarity.split_half_ks(rng.normal(size=400)).rejects_stationarity
        for _ in range(400)
    )
    rate = rejects / 400
    assert 0.01 <= rate <= 0.10, f"iid rejection rate {rate:.3f}"


def test_autocorrelation_inflates_type_i_error():
    """
    KNOWN LIMITATION, measured not assumed.

    An AR(1) with phi=0.95 is marginally stationary, so a correct test would reject
    about 5% of the time. It does not, because KS assumes independence. This test
    asserts the inflation is real and large, and pins the number so a future change
    that silently "fixes" it gets noticed.
    """
    rng = np.random.default_rng(31337)
    rejects = 0
    trials = 200
    for _ in range(trials):
        x = synthetic.synthetic_ar1_window(2000, phi=0.95, rng=rng)
        rejects += stationarity.split_half_ks(x).rejects_stationarity
    rate = rejects / trials
    assert rate > 0.20, (
        f"expected badly inflated type-I error under AR(1), got {rate:.3f}")


def test_thinning_reduces_the_inflation():
    """Thinning to every 40th sample decorrelates enough to pull the rate down."""
    rng = np.random.default_rng(31337)
    thick = thin = 0
    trials = 200
    for _ in range(trials):
        x = synthetic.synthetic_ar1_window(4000, phi=0.95, rng=rng)
        thick += stationarity.split_half_ks(x).rejects_stationarity
        thin += stationarity.split_half_ks(x, thin=40).rejects_stationarity
    assert thin / trials < thick / trials, (thin / trials, thick / trials)


def test_min_detectable_shift_hand_computed():
    """D_crit = 1.358 * sqrt((n1+n2)/(n1*n2)); n1=n2=100 -> 1.358*sqrt(200/10000)."""
    expected = 1.358 * np.sqrt(200 / 10000)
    assert stationarity.min_detectable_shift(100, 100) == pytest.approx(expected)


def test_timestamp_split_differs_from_index_split():
    """
    Non-uniform arrival: 900 points in the first second, 100 in the next nine.
    The index midpoint falls inside the dense burst, the time midpoint does not.
    """
    times = np.concatenate([np.linspace(0, 1, 900), np.linspace(1, 10, 100)])
    values = np.concatenate([np.zeros(900), np.ones(100)])
    by_index = stationarity.split_half_ks(values)
    by_time = stationarity.split_half_ks(values, timestamps=times)
    assert by_index.n_first == 500
    assert by_time.n_first != by_index.n_first
    assert by_time.n_first + by_time.n_second == 1000


def test_rejects_degenerate_input():
    with pytest.raises(ValueError):
        stationarity.split_half_ks([1.0, 2.0])
    with pytest.raises(ValueError):
        stationarity.split_half_ks(np.arange(10.0), thin=0)
    with pytest.raises(ValueError):
        stationarity.split_half_ks(np.arange(10.0), timestamps=np.arange(9.0))
