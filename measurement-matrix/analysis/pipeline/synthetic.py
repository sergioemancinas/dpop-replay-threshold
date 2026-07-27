"""
SYNTHETIC data generators. These produce fabricated numbers, on purpose.

Nothing here models any measured behaviour of Keycloak, Spring Security, Redis or
mTLS. The parameters are chosen to exercise the statistics, not to predict anything.
Output of these functions is not a measurement, and is never
be written to a file that a reader could mistake for one.

Every function name is prefixed `synthetic_` so a grep for the word finds them all.
"""

from __future__ import annotations

import numpy as np

SYNTHETIC_WARNING = (
    "SYNTHETIC: fabricated numbers for pipeline validation. Not a measurement."
)


def synthetic_latency_samples(
    n: int,
    location: float = 2.0,
    scale: float = 0.35,
    tail_fraction: float = 0.01,
    tail_multiplier: float = 6.0,
    rng=None,
) -> np.ndarray:
    """
    Lognormal body with a heavier contaminating tail. SYNTHETIC.

    Lognormal is a common stand-in for request latency and the contamination gives
    the p99 something to bite on. It is a convenient shape, not a claim about any
    real system.
    """
    rng = np.random.default_rng(rng)
    body = rng.lognormal(mean=np.log(location), sigma=scale, size=n)
    n_tail = int(round(n * tail_fraction))
    if n_tail:
        idx = rng.choice(n, size=n_tail, replace=False)
        body[idx] *= tail_multiplier
    return body


def synthetic_p99_replications(
    n_replications: int,
    true_p99: float,
    run_to_run_cv: float = 0.06,
    rng=None,
) -> np.ndarray:
    """
    One p99 per replication, with lognormal run-to-run variation. SYNTHETIC.

    `run_to_run_cv` is the coefficient of variation across replications, the term
    that dominates on shared hardware and the reason the bootstrap resamples
    replications rather than requests.
    """
    rng = np.random.default_rng(rng)
    sigma = np.sqrt(np.log(1.0 + run_to_run_cv ** 2))
    mu = np.log(true_p99) - 0.5 * sigma ** 2
    return rng.lognormal(mean=mu, sigma=sigma, size=n_replications)


def synthetic_stationary_window(n: int, rng=None) -> np.ndarray:
    """IID window with no drift. SYNTHETIC. KS must NOT reject on this."""
    return synthetic_latency_samples(n, rng=rng)


def synthetic_nonstationary_window(
    n: int,
    drift: float = 0.5,
    rng=None,
) -> np.ndarray:
    """
    Window with a linear upward drift in location. SYNTHETIC. KS must reject.

    `drift` is the additive shift, in the same units, between the first and last
    observation.
    """
    rng = np.random.default_rng(rng)
    base = synthetic_latency_samples(n, rng=rng)
    return base + np.linspace(0.0, drift, n)


def synthetic_ar1_window(
    n: int,
    phi: float = 0.95,
    sigma: float = 1.0,
    rng=None,
) -> np.ndarray:
    """
    Stationary AR(1). SYNTHETIC.

    Marginally stationary but strongly autocorrelated, which is what a real latency
    stream looks like. Used to measure how badly the split-half KS false-positive
    rate inflates when the independence assumption fails.
    """
    rng = np.random.default_rng(rng)
    innovations = rng.normal(0.0, sigma, size=n)
    out = np.empty(n, dtype=float)
    # Start from the stationary marginal so there is no burn-in transient, which
    # would itself be a non-stationarity and would confound the type-I measurement.
    out[0] = rng.normal(0.0, sigma / np.sqrt(1.0 - phi ** 2))
    for i in range(1, n):
        out[i] = phi * out[i - 1] + innovations[i]
    return out


def synthetic_condition_set(
    n_replications: int = 20,
    p99_by_condition: dict[str, float] | None = None,
    run_to_run_cv: float = 0.06,
    rng=None,
) -> dict[str, np.ndarray]:
    """
    A dict of condition -> per-replication p99 values. SYNTHETIC.

    Default separations are arbitrary illustrative numbers, NOT predictions for
    C0/D1/D2/D4/M1. They exist so the omnibus and post-hoc tests have something with
    a known ordering to run on.
    """
    if p99_by_condition is None:
        p99_by_condition = {"C0": 8.0, "D1": 8.4, "D2": 11.0, "M1": 9.2}
    rng = np.random.default_rng(rng)
    return {
        name: synthetic_p99_replications(n_replications, value, run_to_run_cv, rng)
        for name, value in p99_by_condition.items()
    }
