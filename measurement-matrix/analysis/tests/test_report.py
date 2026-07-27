"""
End-to-end pipeline behaviour on SYNTHETIC input.

These do not validate the statistics (the per-module tests do that). They validate
the sequencing rules the pre-registration implies: post-hoc only after a significant
omnibus, effect sizes always, stationarity checked before anything else.
"""

import numpy as np
import pytest

from pipeline import report, synthetic


def test_condition_report_meets_target_with_enough_replications():
    p99s = synthetic.synthetic_p99_replications(80, true_p99=10.0,
                                                run_to_run_cv=0.05, rng=1)
    rep = report.condition_report("D1_SYNTHETIC", p99s, n_resamples=4000, rng=1)
    assert rep.meets_target, rep.summary()
    assert rep.replications_required == rep.ci.n


def test_condition_report_demands_more_replications_when_noisy():
    p99s = synthetic.synthetic_p99_replications(6, true_p99=10.0,
                                                run_to_run_cv=0.30, rng=2)
    rep = report.condition_report("D2_SYNTHETIC", p99s, n_resamples=4000, rng=2)
    assert not rep.meets_target
    assert rep.replications_required > rep.ci.n
    assert any("unreliable" in n for n in rep.ci.warnings)


def test_posthoc_is_skipped_when_omnibus_does_not_reject():
    rng = np.random.default_rng(3)
    groups = {f"C{i}_SYNTHETIC": rng.normal(10.0, 1.0, size=40) for i in range(3)}
    comp = report.compare_conditions(groups)
    assert not comp.omnibus.significant
    assert comp.posthoc is None
    # Effect sizes are still reported. Gating them on p would bias the record.
    assert len(comp.effects) == 3
    assert all(e.magnitude == "negligible" for e in comp.effects)


def test_posthoc_runs_and_finds_the_planted_ordering():
    groups = synthetic.synthetic_condition_set(n_replications=40, rng=99)
    comp = report.compare_conditions(groups)
    assert comp.omnibus.significant
    assert comp.posthoc is not None

    pair = next(p for p in comp.posthoc.pairs if {p.a, p.b} == {"C0", "D2"})
    assert pair.significant and pair.z < 0  # D2 planted slower than C0

    eff = next(e for (a, b), e in zip(comp.effect_labels, comp.effects)
               if {a, b} == {"C0", "D2"})
    assert eff.delta < 0 and eff.magnitude == "large"


def test_window_check_flags_a_planted_drift():
    stationary = report.check_window(
        synthetic.synthetic_stationary_window(8000, rng=4))
    drifting = report.check_window(
        synthetic.synthetic_nonstationary_window(8000, drift=0.6, rng=4))
    assert not stationary.rejects_stationarity
    assert drifting.rejects_stationarity


def test_summaries_are_printable():
    groups = synthetic.synthetic_condition_set(n_replications=25, rng=7)
    comp = report.compare_conditions(groups)
    text = comp.summary()
    assert "Kruskal-Wallis" in text and "Cliff's delta" in text
    rep = report.condition_report("D1_SYNTHETIC", groups["D1"], n_resamples=2000,
                                  rng=7)
    assert "median p99" in rep.summary()


def test_compare_conditions_needs_two_groups():
    with pytest.raises(ValueError):
        report.compare_conditions({"only": [1.0, 2.0, 3.0]})
