"""
Glue that runs the pre-registered steps in the pre-registered order.

Order matters and is fixed here so it cannot drift once real data arrives:

  1. Stationarity per measurement window (KS split halves). A window that fails is
     excluded and the exclusion is recorded; it is NOT silently trimmed.
  2. Per-condition BCa CI on median p99 across replications, and the
     replication-count rule against the 5% target.
  3. Kruskal-Wallis omnibus across conditions.
  4. Dunn post-hoc with Holm, ONLY if the omnibus rejects. Running post-hoc tests
     after a non-significant omnibus is a protocol violation, not a judgement call,
     so `compare_conditions` refuses.
  5. Cliff's delta with Romano-Kromrey magnitude for every pair, reported regardless
     of significance. Effect sizes are descriptive; gating them on p-values produces
     a biased effect-size literature.

NO REAL MEASUREMENT DATA EXISTS. These functions take arrays; the only arrays that
have ever been passed to them come from pipeline.synthetic or from tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from . import bca, effect_size, omnibus, stationarity


@dataclass
class ConditionReport:
    name: str
    ci: bca.BcaResult
    replications_required: int
    meets_target: bool
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        verdict = ("target met" if self.meets_target
                   else f"needs ~{self.replications_required} replications")
        lines = [f"{self.name}: median p99 {self.ci.summary()} -> {verdict}"]
        lines += [f"    note: {n}" for n in self.notes + self.ci.warnings]
        return "\n".join(lines)


@dataclass
class ComparisonReport:
    omnibus: omnibus.KruskalResult
    posthoc: omnibus.DunnResult | None
    effects: list[effect_size.CliffsDelta]
    effect_labels: list[tuple[str, str]]

    def summary(self) -> str:
        lines = [self.omnibus.summary()]
        if self.posthoc is None:
            lines.append("post-hoc skipped: omnibus did not reject at alpha")
        else:
            lines.append(self.posthoc.summary())
            for w in self.posthoc.warnings:
                lines.append(f"  warning: {w}")
        lines.append("Effect sizes (Cliff's delta, Romano-Kromrey magnitude):")
        for (a, b), eff in zip(self.effect_labels, self.effects):
            lines.append(f"  {a} vs {b}: {eff.summary()}")
        return "\n".join(lines)


def check_window(values, timestamps=None, alpha: float = 0.05):
    """Step 1. Pre-registered split-half KS, no thinning, no magnitude gate."""
    return stationarity.split_half_ks(values, timestamps, alpha=alpha)


def condition_report(
    name: str,
    p99_values,
    target: float = bca.TARGET_RELATIVE_HALF_WIDTH,
    n_resamples: int = 10000,
    rng=None,
) -> ConditionReport:
    """Step 2. BCa CI on median p99 plus the replication-count rule."""
    p99_values = np.asarray(p99_values, dtype=float).ravel()
    ci = bca.bca_ci(p99_values, bca.median_statistic, 0.95, n_resamples, rng)
    required = bca.replications_for_target_width(ci, target)
    notes = []
    if ci.degenerate:
        notes.append("BCa degenerate; percentile-interval fallback used")
    return ConditionReport(name=name, ci=ci, replications_required=required,
                           meets_target=ci.relative_half_width <= target,
                           notes=notes)


def compare_conditions(groups: dict, alpha: float = 0.05) -> ComparisonReport:
    """Steps 3 to 5. Omnibus, gated post-hoc, ungated effect sizes."""
    kw = omnibus.kruskal_wallis(groups, alpha=alpha)
    posthoc = omnibus.dunn_posthoc(groups, alpha=alpha) if kw.significant else None

    names = list(groups)
    labels, effects = [], []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            labels.append((names[i], names[j]))
            effects.append(effect_size.cliffs_delta(groups[names[i]],
                                                    groups[names[j]]))
    return ComparisonReport(omnibus=kw, posthoc=posthoc, effects=effects,
                            effect_labels=labels)
