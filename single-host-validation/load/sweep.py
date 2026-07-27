"""
R* sweep and replay probe.

Tests the prediction that a bounded process-local jti cache admits DPoP proof replay
if and only if the sustained unique-proof rate exceeds R* = N / W.

Procedure per rate R:
  1. Acquire a DPoP-bound access token.
  2. Issue a probe proof P with jti J at time T. Expect HTTP 200.
  3. Drive unique-jti load at sustained rate R for t seconds.
  4. Replay P verbatim (same jti, same iat) at T + t.
  5. Record the replay status. 200 means the replay was admitted.

Timing note. The cache holds N entries. After t seconds at rate R, R*t insertions have
occurred, so J has been evicted when R*t > N. The replay must also still satisfy iat
validation, which requires t < W. The observed crossover therefore sits at N/t, and the
paper's R* = N/W is the limiting case as t approaches W. This script replays at t = 58 s
by default, 2 s inside the 60 s window, predicting a crossover at 1000/58 = 17.2 req/s.
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

import httpx

from dpop import DPoPKey, decode_claims, fetch_token


async def drive_load(client, url, key, token, rate, duration, stats):
    """Send unique-jti requests at a sustained rate. Returns count of insertions."""
    interval = 1.0 / rate
    start = time.monotonic()
    sent = 0
    tasks = []

    while True:
        target = start + sent * interval
        now = time.monotonic()
        if target - start >= duration:
            break
        if target > now:
            await asyncio.sleep(target - now)

        proof = key.proof("GET", url, access_token=token)
        tasks.append(asyncio.create_task(
            client.get(url, headers={
                "Authorization": f"DPoP {token}",
                "DPoP": proof,
            })
        ))
        sent += 1

    # Every task is retained and awaited. Counting only still-inflight tasks would
    # undercount insertions and misreport what actually entered the cache.
    for r in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(r, httpx.Response):
            stats[r.status_code] = stats.get(r.status_code, 0) + 1
        else:
            stats["error"] = stats.get("error", 0) + 1
    return sent


async def run_rate(base_url, token_endpoint, client_id, username, password,
                   rate, replay_at):
    """Run one rate point. Returns a result dict."""
    url = f"{base_url}/api/resource"
    key = DPoPKey()
    token_response = fetch_token(token_endpoint, key, client_id, username, password)
    token = token_response["access_token"]

    claims = decode_claims(token)
    jkt = claims.get("cnf", {}).get("jkt")
    if jkt != key.thumbprint:
        raise RuntimeError(
            f"access token is not DPoP-bound: cnf.jkt={jkt} "
            f"expected {key.thumbprint}"
        )

    limits = httpx.Limits(max_connections=64, max_keepalive_connections=64)
    async with httpx.AsyncClient(limits=limits, timeout=20.0) as client:
        # Step 2: the probe, issued once and held for replay.
        probe_iat = int(time.time())
        probe_jti = f"probe-{rate}-{probe_iat}"
        probe = key.proof("GET", url, jti=probe_jti, iat=probe_iat,
                          access_token=token)
        first = await client.get(url, headers={
            "Authorization": f"DPoP {token}", "DPoP": probe})
        if first.status_code != 200:
            raise RuntimeError(
                f"probe rejected on first use: {first.status_code} {first.text[:200]}"
            )

        # Step 3: sustained unique-jti load.
        stats = {}
        t0 = time.monotonic()
        sent = await drive_load(client, url, key, token, rate, replay_at, stats)
        elapsed = time.monotonic() - t0

        # Step 4: replay the probe verbatim.
        replay = await client.get(url, headers={
            "Authorization": f"DPoP {token}", "DPoP": probe})

    age = int(time.time()) - probe_iat
    admitted = replay.status_code == 200
    return {
        "rate_req_s": rate,
        "replay_at_s": replay_at,
        "elapsed_s": round(elapsed, 2),
        "probe_age_at_replay_s": age,
        "requests_sent": sent,
        "insertions_2xx": stats.get(200, 0),
        "load_status_counts": {str(k): v for k, v in sorted(stats.items(), key=str)},
        "replay_status": replay.status_code,
        "replay_admitted": admitted,
        "iat_window_respected": age < 60,
    }


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8081")
    parser.add_argument("--token-endpoint",
                        default="http://localhost:8080/realms/dpop-demo/protocol/openid-connect/token")
    parser.add_argument("--client-id", default="demo-client")
    parser.add_argument("--username", default="testuser")
    parser.add_argument("--password", default="testpass")
    parser.add_argument("--rates", default="5,10,15,17,18,20,25,40")
    parser.add_argument("--replay-at", type=float, default=58.0)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--out", default="results/sweep.json")
    args = parser.parse_args()

    rates = [float(r) for r in args.rates.split(",")]
    predicted = 1000.0 / args.replay_at

    print(f"cache bound N = 1000 (Spring Security JtiCache MAX_SIZE)")
    print(f"iat window W = 60 s (JwtIssuedAtValidator default clockSkew)")
    print(f"replay issued at t = {args.replay_at} s")
    print(f"predicted crossover N/t = {predicted:.1f} req/s")
    print(f"paper's limiting threshold N/W = {1000/60:.1f} req/s")
    print()

    results = []
    for rate in rates:
        for rep in range(args.repeats):
            label = f"R={rate:g} req/s" + (f" rep {rep+1}" if args.repeats > 1 else "")
            print(f"{label:24s} running ... ", end="", flush=True)
            try:
                result = await run_rate(
                    args.base_url, args.token_endpoint, args.client_id,
                    args.username, args.password, rate, args.replay_at)
            except Exception as exc:
                print(f"FAILED: {exc}")
                results.append({"rate_req_s": rate, "error": str(exc)})
                continue
            result["repeat"] = rep + 1
            verdict = "ADMITTED" if result["replay_admitted"] else "rejected"
            print(f"{result['insertions_2xx']:5d} insertions, "
                  f"replay HTTP {result['replay_status']} -> {verdict}")
            results.append(result)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "cache_bound_N": 1000,
        "iat_window_W_s": 60,
        "replay_at_s": args.replay_at,
        "predicted_crossover_req_s": round(predicted, 2),
        "limiting_threshold_N_over_W_req_s": round(1000 / 60, 2),
        "results": results,
    }
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {out_path}")

    ok = [r for r in results if "error" not in r]
    rejected = [r["rate_req_s"] for r in ok if not r["replay_admitted"]]
    admitted = [r["rate_req_s"] for r in ok if r["replay_admitted"]]
    print(f"rejected below: {sorted(set(rejected))}")
    print(f"admitted above: {sorted(set(admitted))}")
    if rejected and admitted:
        boundary = (max(rejected), min(admitted))
        print(f"observed transition between {boundary[0]:g} and {boundary[1]:g} req/s")
        if boundary[0] < boundary[1]:
            print("outcome is monotone: consistent with the model")
        else:
            print("outcome is NOT monotone: inspect per-rate results")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
