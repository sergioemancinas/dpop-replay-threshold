"""
Results verifier for the D1 single-host replay sweep.

Runs after reproduce.sh. Confirms a fresh run reproduces the paper's headline
(the admission crossover sits between 17 and 18 req/s) and fails
loudly with a distinct exit code if the host could not sustain the target rate,
instead of silently reporting the claim as false.

The trap this guards against: if a host cannot push the target rate, actual
insertions fall short of N at the rates that should admit, the probe is not
evicted, the replay is rejected, and the headline inverts. That looks identical
to "the claim is false" unless throughput is checked. It is not the same thing.

Exit codes:
  0  every check held; the claim reproduced on this host
  1  model mismatch: throughput was sustained but an observed admission, the
     headline, the iat window, or the adversarial sweep disagreed with the model
  2  host too slow: at least one row fell short of its target insertion count,
     so the result cannot be trusted. This is a limitation of THIS host, NOT
     evidence against the claim.

Checks on results/sweep.json:
  1. per row  replay_admitted == (rate_req_s * elapsed_s > cache_bound_N)
  2. headline every rate <= 17 rejects, every rate >= 18 admits
  3. guard    requests_sent >= 0.98 * rate_req_s * replay_at_s
  4. window   iat_window_respected is true on every row
Optional adversarial/results/t_sweep.json:
  5. per row  admitted == (rate * t > N)
"""

import argparse
import json
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_TOO_SLOW = 2

HERE = Path(__file__).resolve().parent
DEFAULT_SWEEP = HERE / "results" / "sweep.json"
DEFAULT_T_SWEEP = HERE / "adversarial" / "results" / "t_sweep.json"

GUARD = 0.98       # a row must reach at least this fraction of its target sends
LOW_REJECT = 17.0  # every rate at or below this must reject
HIGH_ADMIT = 18.0  # every rate at or above this must admit


def label(admitted):
    return "admit" if admitted else "reject"


def check_sweep(path, data):
    """Verify the D1 sweep. Returns (mismatch, too_slow)."""
    N = data["cache_bound_N"]
    W = data["iat_window_W_s"]
    rows = [r for r in data["results"] if "error" not in r]
    errored = [r for r in data["results"] if "error" in r]

    print(f"D1 sweep: {path}")
    print(f"cache bound N = {N}, iat window W = {W} s")
    if errored:
        print(f"WARNING: {len(errored)} row(s) recorded an error and were skipped")
    print()

    mismatch = False
    too_slow = False

    # Check 1: per-row admission model.
    print("admission model  replay_admitted == (rate * elapsed > N)")
    for r in rows:
        rate = r["rate_req_s"]
        elapsed = r.get("elapsed_s", r["replay_at_s"])
        predicted = rate * elapsed > N
        ok = r["replay_admitted"] == predicted
        mismatch = mismatch or not ok
        print(f"  {'PASS' if ok else 'FAIL'}  R={rate:5g} req/s  "
              f"rate*elapsed={rate * elapsed:8.1f}  "
              f"predict {label(predicted):6s}  observed {label(r['replay_admitted'])}")
    print()

    # Check 3: throughput guard. Checked before the verdict so slowness is never
    # mistaken for a false claim.
    print(f"throughput guard  requests_sent >= {GUARD:g} * rate * replay_at")
    for r in rows:
        rate = r["rate_req_s"]
        target = rate * r["replay_at_s"]
        floor = GUARD * target
        sent = r["requests_sent"]
        ok = sent >= floor
        too_slow = too_slow or not ok
        print(f"  {'PASS' if ok else 'TOO SLOW':8s}  R={rate:5g} req/s  "
              f"sent={sent:5d}  target={target:7.0f}  floor={floor:7.0f}")
    print()

    # Check 4: iat window respected.
    print("iat window  iat_window_respected is true on every row")
    for r in rows:
        ok = bool(r.get("iat_window_respected"))
        mismatch = mismatch or not ok
        print(f"  {'PASS' if ok else 'FAIL'}  R={r['rate_req_s']:5g} req/s  "
              f"age={r.get('probe_age_at_replay_s')} s")
    print()

    # Check 2: headline transition.
    rejected = sorted({r["rate_req_s"] for r in rows if not r["replay_admitted"]})
    admitted = sorted({r["rate_req_s"] for r in rows if r["replay_admitted"]})
    bad = sorted({r["rate_req_s"] for r in rows
                  if (r["rate_req_s"] <= LOW_REJECT and r["replay_admitted"])
                  or (r["rate_req_s"] >= HIGH_ADMIT and not r["replay_admitted"])})
    print(f"headline  rates <= {LOW_REJECT:g} reject, rates >= {HIGH_ADMIT:g} admit")
    if bad:
        mismatch = True
        print(f"  FAIL  headline violated at rates {bad}")
    else:
        print(f"  PASS  rejected {rejected}")
        print(f"        admitted {admitted}")
    if rejected and admitted:
        print(f"  observed transition between {max(rejected):g} "
              f"and {min(admitted):g} req/s")
    print()

    return mismatch, too_slow


def check_t_sweep(path, data):
    """Verify the adversarial fixed-R swept-t sweep. Returns mismatch."""
    N = data["N"]
    rows = data["rows"]
    print(f"adversarial t sweep: {path}")
    print(f"N = {N}")
    print("admission model  admitted == (rate * t > N)")
    mismatch = False
    for r in rows:
        rate = r["rate"]
        t = r["t"]
        predicted = rate * t > N
        ok = r["admitted"] == predicted
        mismatch = mismatch or not ok
        print(f"  {'PASS' if ok else 'FAIL'}  R={rate:3g} t={t:3g}  "
              f"rate*t={rate * t:6g}  predict {label(predicted):6s}  "
              f"observed {label(r['admitted'])}")
    print()
    return mismatch


def main():
    parser = argparse.ArgumentParser(description="Verify a D1 replay sweep run.")
    parser.add_argument("--sweep", default=str(DEFAULT_SWEEP))
    parser.add_argument("--t-sweep", default=str(DEFAULT_T_SWEEP))
    args = parser.parse_args()

    sweep_path = Path(args.sweep)
    if not sweep_path.exists():
        print(f"ERROR: {sweep_path} not found. Run reproduce.sh first.")
        return EXIT_MISMATCH

    mismatch, too_slow = check_sweep(sweep_path, json.loads(sweep_path.read_text()))

    t_sweep_path = Path(args.t_sweep)
    if t_sweep_path.exists():
        t_mismatch = check_t_sweep(t_sweep_path, json.loads(t_sweep_path.read_text()))
        mismatch = mismatch or t_mismatch
    else:
        print(f"adversarial t sweep: {t_sweep_path} not present, skipping")
        print()

    print("=" * 62)
    # Slowness is reported first and on its own. It explains any admission
    # disagreement above, so it must never be relabeled as a false claim.
    if too_slow:
        print("RESULT: HOST WAS TOO SLOW")
        print("At least one row fell short of its target insertion count. At the")
        print("rates that should admit, insertions did not reach N, so the replay")
        print("outcome and the headline can invert. This is a limitation of THIS")
        print("host, NOT evidence against the claim. Re-run on a host that can")
        print("sustain the target rate.")
        return EXIT_TOO_SLOW
    if mismatch:
        print("RESULT: MODEL MISMATCH")
        print("Throughput was sustained, so this is a genuine disagreement with the")
        print("model. The claim did NOT reproduce on this run.")
        return EXIT_MISMATCH
    print("RESULT: claim reproduced")
    print("Every row matches the admission model, the headline transition sits")
    print("between 17 and 18 req/s, throughput was sustained on every row, and the")
    print("iat window held.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
