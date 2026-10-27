"""
Spring Security 7.1.2 follow-up: does the replacement replay cache close the bounded-cache
replay, and where does its per-key limit start rejecting honest traffic?

Three experiments against the stack in this directory, predictions in README.md:
  A  replay negative control: probe, unique-jti load at rate R, replay at t = 28 s
  B  attacker flood: 1050 proofs under the attacker's own key, then replay the victim proof
  C  per-key limit: one client key at rate R for 70 s, every response status recorded

Usage: python3 probe.py [A|B|C|all]   (writes results/<experiment>.json)
"""

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "single-host-validation" / "load"))
from dpop import DPoPKey, decode_claims, fetch_token  # noqa: E402

URL = "http://localhost:8081/api/resource"
TOKEN_ENDPOINT = "http://localhost:8080/realms/dpop-demo/protocol/openid-connect/token"
WINDOW_S = 30          # DPoPProofJwtDecoderFactory clockSkew in 7.1.2
REPLAY_AT_S = 28.0     # inside the window, 2 s guard band as in the 6.5.5 sweep
RATES_A = [5, 17, 18, 25, 40]
RATES_C = [15, 20, 24, 26, 28, 30, 32, 35, 40, 50]
DURATION_C_S = 70.0


def bound_client():
    """A fresh key and a DPoP-bound token for it; refuses an unbound token."""
    key = DPoPKey()
    token = fetch_token(TOKEN_ENDPOINT, key, "demo-client", "testuser", "testpass")["access_token"]
    jkt = decode_claims(token).get("cnf", {}).get("jkt")
    if jkt != key.thumbprint:
        raise RuntimeError(f"token not DPoP-bound: cnf.jkt={jkt}")
    return key, token


def headers(token, proof):
    return {"Authorization": f"DPoP {token}", "DPoP": proof}


async def paced(client, key, token, rate, duration):
    """Unique-jti requests at a fixed rate. Returns [(t_send_s, status)] for every request."""
    start = time.monotonic()
    sends, tasks, i = [], [], 0
    while (target := i / rate) < duration:
        if (delay := start + target - time.monotonic()) > 0:
            await asyncio.sleep(delay)
        sends.append(round(time.monotonic() - start, 3))
        tasks.append(asyncio.create_task(
            client.get(URL, headers=headers(token, key.proof("GET", URL, access_token=token)))))
        i += 1
    out = await asyncio.gather(*tasks, return_exceptions=True)
    return [(t, r.status_code if isinstance(r, httpx.Response) else "error") for t, r in zip(sends, out)]


def counts(rows):
    c = {}
    for _, s in rows:
        c[str(s)] = c.get(str(s), 0) + 1
    return c


async def experiment_a():
    results = []
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=64), timeout=20.0) as client:
        for rate in RATES_A:
            key, token = bound_client()
            iat = int(time.time())
            probe = key.proof("GET", URL, jti=f"probe-{rate}-{iat}", iat=iat, access_token=token)
            first = (await client.get(URL, headers=headers(token, probe))).status_code
            rows = await paced(client, key, token, rate, REPLAY_AT_S)
            replay = (await client.get(URL, headers=headers(token, probe))).status_code
            age = int(time.time()) - iat
            results.append({"rate_req_s": rate, "probe_first_use": first, "load_status_counts": counts(rows),
                            "replay_status": replay, "replay_admitted": replay == 200,
                            "probe_age_at_replay_s": age, "iat_window_respected": age < WINDOW_S})
            print(f"A  R={rate:>3} req/s  load {counts(rows)}  replay HTTP {replay}")
    return {"replay_at_s": REPLAY_AT_S, "window_s": WINDOW_S, "results": results}


async def experiment_b():
    async with httpx.AsyncClient(timeout=20.0) as client:
        victim, token = bound_client()
        captured = victim.proof("GET", URL, jti="victim-captured-proof", iat=int(time.time()), access_token=token)
        first = (await client.get(URL, headers=headers(token, captured))).status_code
        replay_before = (await client.get(URL, headers=headers(token, captured))).status_code
        attacker, flood = DPoPKey(), {}
        for i in range(1050):
            p = attacker.proof("GET", URL, jti=f"attacker-{i}", iat=int(time.time()), access_token=token)
            s = (await client.get(URL, headers=headers(token, p))).status_code
            flood[str(s)] = flood.get(str(s), 0) + 1
        replay_after = (await client.get(URL, headers=headers(token, captured))).status_code
    print(f"B  victim first use {first}, replay before {replay_before}, flood {flood}, replay after {replay_after}")
    return {"victim_first_use": first, "replay_before_flood": replay_before, "flood_status_counts": flood,
            "replay_after_flood": replay_after, "replay_admitted": replay_after == 200}


async def experiment_c():
    results = []
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=128), timeout=20.0) as client:
        for rate in RATES_C:
            key, token = bound_client()
            rows = await paced(client, key, token, rate, DURATION_C_S)
            rejected = [t for t, s in rows if s != 200]
            tail = [s for t, s in rows if t >= DURATION_C_S - 30]
            accepted_tail = sum(1 for s in tail if s == 200) / 30
            results.append({"rate_req_s": rate, "duration_s": DURATION_C_S, "status_counts": counts(rows),
                            "first_rejection_s": rejected[0] if rejected else None,
                            "accepted_rate_last_30s": round(accepted_tail, 2), "per_request": rows})
            print(f"C  R={rate:>3} req/s  {counts(rows)}  first rejection at "
                  f"{rejected[0] if rejected else '-'} s  accepted last 30 s: {accepted_tail:.1f} req/s")
            await asyncio.sleep(WINDOW_S + 12)  # let this key's entries expire and be cleaned
    return {"duration_s": DURATION_C_S, "results": results}


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    runs = {"A": experiment_a, "B": experiment_b, "C": experiment_c}
    (HERE / "results").mkdir(exist_ok=True)
    for name in (runs if which == "all" else [which]):
        data = asyncio.run(runs[name]())
        data["run_finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (HERE / "results" / f"{name}.json").write_text(json.dumps(data, indent=1))


if __name__ == "__main__":
    main()
