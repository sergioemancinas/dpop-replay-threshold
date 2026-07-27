"""
E3: break the R / R*t confound by sweeping the replay delay t at fixed rate R.

The main sweep (sweep.py) fixed t = 58 s and varied R, so R and the insertion count R*t
were collinear across the whole design. A reviewer correctly noted that every observation
there is equally explained by "the 1000th subsequent insertion evicts the probe", which
follows from reading MAX_SIZE = 1000 and needs no experiment.

This probe fixes R and varies t. If the admission boundary is genuinely the eviction
condition R*t > N, the crossover in t must sit at t* = N/R and must MOVE when R changes.
Two rates are swept:

  R = 20 req/s  ->  predicted crossover t* = 1000/20 = 50 s
  R = 40 req/s  ->  predicted crossover t* = 1000/40 = 25 s

A moving crossover cannot be explained by a rate-free "1000th insertion" statement, and it
cannot be explained by t alone. It requires the product R*t, i.e. two degrees of freedom.
The replay is always issued inside the iat window (t < 60 s), so iat validity is not the
cause of any rejection here; that boundary is pinned separately by iat_window_probe.py.
"""

import argparse
import asyncio
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))
from dpop import DPoPKey, fetch_token  # noqa: E402

BASE = "http://localhost:8081"
URL = f"{BASE}/api/resource"
TOKEN_ENDPOINT = "http://localhost:8080/realms/dpop-demo/protocol/openid-connect/token"


async def drive(client, key, token, rate, duration):
    interval = 1.0 / rate
    start = time.monotonic()
    sent = 0
    tasks = []
    while time.monotonic() - start < duration:
        target = start + sent * interval
        now = time.monotonic()
        if target > now:
            await asyncio.sleep(target - now)
        proof = key.proof("GET", URL, access_token=token)
        tasks.append(asyncio.create_task(client.get(
            URL, headers={"Authorization": f"DPoP {token}", "DPoP": proof})))
        sent += 1
    codes = {}
    for r in await asyncio.gather(*tasks, return_exceptions=True):
        if isinstance(r, httpx.Response):
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
    return sent, codes


async def run_point(rate, t):
    key = DPoPKey()
    token = fetch_token(TOKEN_ENDPOINT, key, "demo-client", "testuser", "testpass")["access_token"]
    limits = httpx.Limits(max_connections=64, max_keepalive_connections=64)
    async with httpx.AsyncClient(limits=limits, timeout=20.0) as client:
        iat = int(time.time())
        probe = key.proof("GET", URL, jti=f"tprobe-{rate}-{t}-{iat}", iat=iat,
                          access_token=token)
        first = await client.get(URL, headers={
            "Authorization": f"DPoP {token}", "DPoP": probe})
        if first.status_code != 200:
            raise RuntimeError(f"probe not accepted: {first.status_code}")
        sent, codes = await drive(client, key, token, rate, t)
        replay = await client.get(URL, headers={
            "Authorization": f"DPoP {token}", "DPoP": probe})
    age = int(time.time()) - iat
    return {"rate": rate, "t": t, "inserts": codes.get(200, 0), "sent": sent,
            "replay": replay.status_code, "admitted": replay.status_code == 200,
            "age": age, "in_window": age < 60}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../results/t_sweep.json")
    args = ap.parse_args()

    plan = [(20, [40, 48, 52, 58]), (40, [18, 24, 28, 35])]
    rows = []
    for rate, ts in plan:
        print(f"R = {rate} req/s, predicted crossover t* = {1000/rate:.0f} s")
        for t in ts:
            r = await run_point(rate, t)
            v = "ADMITTED" if r["admitted"] else "rejected"
            print(f"  t={t:2d}s  R*t={rate*t:4d}  inserts={r['inserts']:4d}  "
                  f"replay {r['replay']} -> {v}  (probe age {r['age']}s, in window={r['in_window']})")
            rows.append(r)
        print()

    import json
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"N": 1000, "plan": "fixed R, swept t", "rows": rows}, indent=2))
    print(f"wrote {out}")

    # Report the observed crossover per rate.
    for rate, _ in plan:
        pts = [r for r in rows if r["rate"] == rate]
        rej = [r["t"] for r in pts if not r["admitted"]]
        adm = [r["t"] for r in pts if r["admitted"]]
        if rej and adm:
            print(f"R={rate}: rejected up to t={max(rej)}s, admitted from t={min(adm)}s, "
                  f"predicted t*={1000/rate:.0f}s")
    print("If the two crossovers differ (near 50 s and 25 s), the outcome depends on R*t,")
    print("not on a rate-free insertion count and not on t alone.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
