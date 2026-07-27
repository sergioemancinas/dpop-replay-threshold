"""
Measure the true width of the iat acceptance window.

JwtIssuedAtValidator rejects when issuedAt is before now-clockSkew or after
now+clockSkew. For a FIXED iat that is a two-sided test, so the interval of wall-clock
times during which one proof stays acceptable is 2*clockSkew wide, not clockSkew.

The distinction matters for the sizing rule. A replay of an honestly issued proof gets
only the forward half, 60 s. A client that sets iat into the future gets the whole 120 s,
and a cache must retain that jti for the whole of it or the proof becomes replayable.

Prints a table and exits non-zero if the observed span contradicts 2*clockSkew.
"""

import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))
from dpop import DPoPKey, fetch_token  # noqa: E402

BASE = "http://localhost:8081"
URL = f"{BASE}/api/resource"
TOKEN_ENDPOINT = "http://localhost:8080/realms/dpop-demo/protocol/openid-connect/token"


def probe(client, token, key, offset):
    """Present a proof whose iat is `offset` seconds from now. Returns status."""
    proof = key.proof("GET", URL, iat=int(time.time()) + offset, access_token=token)
    return client.get(URL, headers={
        "Authorization": f"DPoP {token}", "DPoP": proof}).status_code


def main():
    key = DPoPKey()
    token = fetch_token(TOKEN_ENDPOINT, key, "demo-client", "testuser", "testpass")["access_token"]
    failures = []

    with httpx.Client(timeout=20.0) as client:
        print("Part 1: acceptance as a function of iat offset from now")
        edges = {}
        for offset in (-130, -120, -90, -61, -59, -30, 0, 30, 59, 61, 90, 120, 130):
            status = probe(client, token, key, offset)
            edges[offset] = status
            mark = "accept" if status == 200 else "reject"
            print(f"  iat = now {offset:+5d} s  ->  {status}  {mark}")

        accepted = [o for o, s in edges.items() if s == 200]
        span = max(accepted) - min(accepted)
        print(f"\n  accepted offsets span {min(accepted):+d} to {max(accepted):+d} "
              f"= {span} s")
        if span < 100:
            failures.append(f"expected a span near 120 s, observed {span}")

        # Part 2: the consequence. A proof minted with a future iat is accepted now and
        # remains acceptable well past the 60 s that a naive reading of clockSkew implies.
        print("\nPart 2: how long one future-dated proof stays usable")
        future_iat = int(time.time()) + 55
        proof = key.proof("GET", URL, jti=f"future-{future_iat}", iat=future_iat,
                          access_token=token)
        first = client.get(URL, headers={
            "Authorization": f"DPoP {token}", "DPoP": proof}).status_code
        print(f"  t=0 s   first use            -> {first}")
        if first != 200:
            failures.append("future-dated proof was not accepted on first use")

        # Same jti, so a rejection here is the cache, not the window. Use a sibling proof
        # with the same iat but a fresh jti to isolate the window.
        for wait in (60, 100):
            time.sleep(wait - (0 if wait == 60 else 60))
            sibling = key.proof("GET", URL, jti=f"future-{future_iat}-{wait}",
                                iat=future_iat, access_token=token)
            status = client.get(URL, headers={
                "Authorization": f"DPoP {token}", "DPoP": sibling}).status_code
            age = int(time.time()) - future_iat
            print(f"  t={wait} s  fresh jti, same iat  -> {status} "
                  f"(iat is now {age:+d} s old)")
            if wait == 60 and status != 200:
                failures.append(
                    "a proof still inside the two-sided window was rejected at t=60")

    print()
    if failures:
        for f in failures:
            print("FAIL:", f)
        return 1
    print("Observed window is two-sided and ~120 s wide, as the validator source implies.")
    print("A cache must therefore retain a jti for 2*clockSkew, not clockSkew.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
