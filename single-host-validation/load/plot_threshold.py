"""
Plot cache hold time against sustained request rate, with observed replay outcomes.

The curve is the model: hold time N/R. The horizontal line is the replay instant t.
Where the curve falls below t, the probe has been evicted before it is replayed, so
replay is admitted. Markers are measured outcomes, not model output.
"""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="infile", default="../results/sweep.json")
    parser.add_argument("--out", dest="outfile", default="../results/fig_threshold.pdf")
    args = parser.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed, skipping plot", file=sys.stderr)
        return 0

    with open(args.infile) as handle:
        data = json.load(handle)

    N = data["cache_bound_N"]
    W = data["iat_window_W_s"]
    t_replay = data["replay_at_s"]
    results = [r for r in data["results"] if "error" not in r]

    rates = sorted({r["rate_req_s"] for r in results})
    admitted = sorted({r["rate_req_s"] for r in results if r["replay_admitted"]})
    rejected = sorted({r["rate_req_s"] for r in results if not r["replay_admitted"]})

    fig, ax = plt.subplots(figsize=(6.0, 3.6))

    lo, hi = min(rates) * 0.6, max(rates) * 1.15
    curve_x = [lo + (hi - lo) * i / 400 for i in range(401)]
    ax.plot(curve_x, [N / x for x in curve_x], linewidth=1.6,
            label=f"cache hold time $N/R$ ($N={N}$)")

    ax.axhline(t_replay, linestyle="--", linewidth=1.1, color="0.35",
               label=f"replay issued at $t={t_replay:g}$ s")
    ax.axhline(W, linestyle=":", linewidth=1.1, color="0.55",
               label=f"iat window $W={W}$ s")

    ax.plot(rejected, [N / r for r in rejected], "o", markersize=6,
            markerfacecolor="white", markeredgewidth=1.4,
            label="replay rejected (measured)")
    ax.plot(admitted, [N / r for r in admitted], "X", markersize=8,
            label="replay admitted (measured)")

    if rejected and admitted:
        boundary = (max(rejected) + min(admitted)) / 2
        ax.axvline(boundary, linewidth=1.0, color="0.2", alpha=0.5)
        ax.annotate(f"observed transition\n{max(rejected):g}-{min(admitted):g} req/s",
                    xy=(boundary, N / boundary), xytext=(boundary * 1.05, N / boundary * 1.9),
                    fontsize=8,
                    arrowprops=dict(arrowstyle="->", linewidth=0.8, color="0.2"))

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("sustained unique-proof rate $R$ (req/s per node)")
    ax.set_ylabel("cache hold time (s)")
    ax.grid(True, which="both", alpha=0.25, linewidth=0.5)
    ax.legend(fontsize=7.5, loc="upper right", framealpha=0.95)
    fig.tight_layout()
    fig.savefig(args.outfile)
    print(f"wrote {args.outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
