"""
Correctness suite for the single-host DPoP resource server.

Runs before any measurement. Establishes that the replay defence works as documented
under normal conditions, so that admission observed during the R* sweep is attributable
to cache eviction rather than to a broken deployment.

Tests requiring Redis or multiple replicas are reported SKIP, never PASS.

Validation happens in two places in Spring Security 6.5, which is why the expectations
below differ by claim:
  - htm, htu, jti, iat        DPoPProofJwtDecoderFactory default validator chain
  - ath, jkt                  DPoPAuthenticationProvider
"""

import math
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))
from dpop import OMIT, DPoPKey, decode_claims, fetch_token  # noqa: E402

BASE_URL = "http://localhost:8081"
URL = f"{BASE_URL}/api/resource"
TOKEN_ENDPOINT = "http://localhost:8080/realms/dpop-demo/protocol/openid-connect/token"

results = []


def record(name, expected, actual, detail=""):
    status = "PASS" if expected == actual else "FAIL"
    results.append((status, name, f"expected {expected}, got {actual}", detail))
    print(f"  {status}  {name:52s} expected {expected}, got {actual} {detail}")
    return status == "PASS"


def skip(name, reason):
    results.append(("SKIP", name, reason, ""))
    print(f"  SKIP  {name:52s} {reason}")


def call(client, token, proof, scheme="DPoP"):
    return client.get(URL, headers={
        "Authorization": f"{scheme} {token}", "DPoP": proof}, timeout=15.0)


def main():
    key = DPoPKey()
    token_response = fetch_token(TOKEN_ENDPOINT, key, "demo-client",
                                 "testuser", "testpass")
    token = token_response["access_token"]

    print("\nPreconditions")
    record("token_type is DPoP", "DPoP", token_response.get("token_type"))
    claims = decode_claims(token)
    record("access token carries cnf.jkt bound to client key",
           key.thumbprint, claims.get("cnf", {}).get("jkt"))

    with httpx.Client() as client:
        print("\nBaseline")
        proof = key.proof("GET", URL, access_token=token)
        record("valid proof accepted", 200, call(client, token, proof).status_code)

        print("\njti single-use (RFC 9449 Sec. 11.1)")
        record("same proof replayed at idle is rejected", 401,
               call(client, token, proof).status_code)
        record("fresh jti accepted after a rejection", 200,
               call(client, token,
                    key.proof("GET", URL, access_token=token)).status_code)
        record("absent jti claim rejected", 401,
               call(client, token,
                    key.proof("GET", URL, jti=OMIT,
                              access_token=token)).status_code)
        record("blank jti claim rejected", 401,
               call(client, token,
                    key.proof("GET", URL, jti="", access_token=token)).status_code)

        print("\niat acceptance window (JwtIssuedAtValidator, clockSkew 60 s)")
        now = int(time.time())
        record("iat 30 s in the past accepted", 200,
               call(client, token, key.proof("GET", URL, iat=now - 30,
                                             access_token=token)).status_code)
        record("iat 120 s in the past rejected", 401,
               call(client, token, key.proof("GET", URL, iat=now - 120,
                                             access_token=token)).status_code)
        record("clock skew -2 s tolerated", 200,
               call(client, token, key.proof("GET", URL, iat=now - 2,
                                             access_token=token)).status_code)
        record("clock skew +2 s tolerated", 200,
               call(client, token, key.proof("GET", URL, iat=now + 2,
                                             access_token=token)).status_code)

        # iat is integer seconds, so a nominal age of 59 s is really 59 s plus the
        # sub-second truncation remainder plus request latency. Rounding up on the
        # accept case and down on the reject case removes that ambiguity without
        # widening the interval being tested.
        print("\niat window edges (60 s boundary)")
        record("iat at window minus 1 s accepted", 200,
               call(client, token,
                    key.proof("GET", URL, iat=math.ceil(time.time()) - 59,
                              access_token=token)).status_code, "boundary")
        record("iat at window plus 1 s rejected", 401,
               call(client, token,
                    key.proof("GET", URL, iat=math.floor(time.time()) - 61,
                              access_token=token)).status_code, "boundary")

        print("\nBinding claims")
        wrong_method = key.proof("POST", URL, access_token=token)
        record("htm mismatch rejected", 401,
               call(client, token, wrong_method).status_code)
        wrong_uri = key.proof("GET", f"{BASE_URL}/api/other", access_token=token)
        record("htu mismatch rejected", 401,
               call(client, token, wrong_uri).status_code)
        no_ath = key.proof("GET", URL)
        record("missing ath rejected", 401, call(client, token, no_ath).status_code)
        bad_ath = key.proof("GET", URL, access_token="not-the-real-token")
        record("ath mismatch rejected", 401, call(client, token, bad_ath).status_code)

        print("\nToken presentation")
        record("DPoP-bound token presented as Bearer rejected", 401,
               call(client, token, key.proof("GET", URL, access_token=token),
                    scheme="Bearer").status_code)

        print("\nNot executed in the single-host configuration")
        skip("jti rejection across replicas", "requires 3 replicas, future work")
        skip("Redis primary loss fails closed", "requires Redis, future work")

    passed = sum(1 for r in results if r[0] == "PASS")
    failed = sum(1 for r in results if r[0] == "FAIL")
    skipped = sum(1 for r in results if r[0] == "SKIP")
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    if failed:
        print("\nFAILURES")
        for status, name, detail, extra in results:
            if status == "FAIL":
                print(f"  {name}: {detail} {extra}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
