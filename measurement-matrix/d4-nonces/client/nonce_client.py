"""
Smoke check for the D4 stack: RFC 9449 Section 9 challenge, retry, and replay rejection.

NOT EXECUTED. Running it requires `docker compose up` on the stack in the parent
directory, which was not done. The executed evidence for D4 is the JVM test suite under
`../resource-server/src/test`, which exercises the same code paths in process.

Key handling and token acquisition are reused from the D1 driver rather than duplicated.
Only proof construction is local, because that driver has no nonce claim.
"""

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT / "single-host-validation" / "load"))

from dpop import DPoPKey, b64url, decode_claims, fetch_token  # noqa: E402

NONCE_HEADER = "DPoP-Nonce"


def nonce_proof(key: DPoPKey, htm: str, htu: str, access_token: str,
                nonce: str = None, jti: str = None, iat: int = None) -> str:
    """
    A DPoP proof carrying the nonce claim of RFC 9449 Section 8, Figure 21.

    jti and iat are explicit so a proof can be replayed verbatim. Replay means presenting
    the identical proof, not minting a fresh one.
    """
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk}
    payload = {
        "htm": htm,
        "htu": htu,
        "jti": jti or str(uuid.uuid4()),
        "iat": iat if iat is not None else int(time.time()),
        "ath": b64url(hashlib.sha256(access_token.encode("ascii")).digest()),
    }
    if nonce is not None:
        payload["nonce"] = nonce
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + b64url(key.sign(signing_input))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", default="http://localhost:8090/realms/dpop-demo")
    parser.add_argument("--resource", default="http://localhost:8091/api/resource")
    parser.add_argument("--client-id", default="demo-client")
    parser.add_argument("--username", default="testuser")
    parser.add_argument("--password", default="testpass")
    args = parser.parse_args()

    key = DPoPKey()
    token_endpoint = f"{args.issuer}/protocol/openid-connect/token"
    token = fetch_token(token_endpoint, key, args.client_id, args.username, args.password)
    access_token = token["access_token"]

    cnf = decode_claims(access_token).get("cnf", {})
    if cnf.get("jkt") != key.thumbprint:
        print(f"FAIL: cnf.jkt {cnf.get('jkt')!r} does not match client key")
        return 1

    headers = {"Authorization": f"DPoP {access_token}"}
    failures = []

    with httpx.Client(timeout=30.0) as http:
        # 1. No nonce. RFC 9449 Section 9 Figure 24: 401 with use_dpop_nonce and a nonce.
        first = http.get(args.resource, headers={
            **headers, "DPoP": nonce_proof(key, "GET", args.resource, access_token)})
        nonce = first.headers.get(NONCE_HEADER)
        print(f"no nonce            -> {first.status_code} "
              f"{first.headers.get('WWW-Authenticate')!r} nonce={bool(nonce)}")
        if first.status_code != 401 or "use_dpop_nonce" not in (
                first.headers.get("WWW-Authenticate") or "") or not nonce:
            failures.append("expected 401 use_dpop_nonce with a DPoP-Nonce header")

        # 2. Retry with the supplied nonce. Expect 200 and a rotated nonce.
        probe_jti, probe_iat = str(uuid.uuid4()), int(time.time())
        probe = nonce_proof(key, "GET", args.resource, access_token,
                            nonce=nonce, jti=probe_jti, iat=probe_iat)
        accepted = http.get(args.resource, headers={**headers, "DPoP": probe})
        print(f"with nonce          -> {accepted.status_code} "
              f"rotated={bool(accepted.headers.get(NONCE_HEADER))}")
        if accepted.status_code != 200:
            failures.append("expected 200 for a proof carrying a valid nonce")

        # 3. Replay the accepted proof verbatim. The nonce was spent on its first use, so
        #    the rejection does not depend on the jti cache still holding probe_jti.
        replay = http.get(args.resource, headers={**headers, "DPoP": probe})
        print(f"replay              -> {replay.status_code} "
              f"{replay.headers.get('WWW-Authenticate')!r}")
        if replay.status_code != 401:
            failures.append("expected 401 for a replayed proof")

    for failure in failures:
        print(f"FAIL: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
