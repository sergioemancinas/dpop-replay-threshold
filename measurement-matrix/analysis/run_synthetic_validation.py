#!/usr/bin/env python3
"""
Run the whole pre-registered pipeline on SYNTHETIC input and print the result.

This is a smoke demonstration of the analysis path, not a measurement. It writes
nothing to disk, deliberately: there must be no file in this repository that could
be read as a result for conditions C0/D1/D2/D4/M1/X1/X2, because none of them have
been run.

    python3 run_synthetic_validation.py [--seed N] [--replications N]
"""

import argparse
import sys

from pipeline import NO_REAL_DATA_BANNER, bca, hdr, report, synthetic


def rule(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20260727)
    ap.add_argument("--replications", type=int, default=24)
    ap.add_argument("--window-size", type=int, default=20000)
    args = ap.parse_args(argv)

    print("=" * 78)
    print(NO_REAL_DATA_BANNER)
    print("=" * 78)

    rule("1. Stationarity, split-half Kolmogorov-Smirnov (pre-registered)")
    good = synthetic.synthetic_stationary_window(args.window_size, rng=args.seed)
    bad = synthetic.synthetic_nonstationary_window(args.window_size, drift=0.5,
                                                   rng=args.seed)
    print("  synthetic stationary window   :", report.check_window(good).summary())
    print("  synthetic drifting window     :", report.check_window(bad).summary())

    rule("2. Median p99 BCa 95% CI and the replication-count rule")
    groups = synthetic.synthetic_condition_set(n_replications=args.replications,
                                               rng=args.seed)
    for name, values in groups.items():
        print(report.condition_report(f"{name}_SYNTHETIC", values,
                                      rng=args.seed).summary())
    print(f"  target: half-width <= {bca.TARGET_RELATIVE_HALF_WIDTH:.0%} "
          "of median p99")

    rule("3-5. Kruskal-Wallis, Dunn/Holm, Cliff's delta")
    print(report.compare_conditions(groups).summary())

    rule("6. HdrHistogram ingestion, synthetic fixture")
    fixture = ("tests/fixtures/SYNTHETIC_NOT_A_MEASUREMENT_wrk2.txt")
    try:
        dist = hdr.parse_percentile_distribution(fixture)
        blocks = hdr.parse_wrk2_latency_summary(fixture)
        print(f"  detailed spectrum: n={dist.total_count} p99={dist.p99:.3f} ms")
        for b in blocks:
            print(f"  summary block {b.label!r}: "
                  f"p99={b.value_at_percentile(99.0):.3f} ms")
    except OSError:
        print("  fixture not found; run from the analysis directory")

    print()
    print("=" * 78)
    print(NO_REAL_DATA_BANNER)
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
