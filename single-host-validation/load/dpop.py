"""
DPoP client primitives: key handling, proof construction, token acquisition.

Proofs are ES256 per RFC 9449 and FAPI 2.0. Nothing here is specific to the replay
experiment; sweep.py and correctness.py both build on it.
"""

import base64
import hashlib
import json
import time
import uuid

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.hazmat.primitives import hashes


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class _Omit:
    """Sentinel: leave a claim out of the proof entirely."""

    def __repr__(self):
        return "OMIT"


OMIT = _Omit()


class DPoPKey:
    """An EC P-256 keypair with its JWK representation and thumbprint."""

    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.private_key.public_key().public_numbers()
        self.jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(numbers.x.to_bytes(32, "big")),
            "y": b64url(numbers.y.to_bytes(32, "big")),
        }

    @property
    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint, the value that appears as cnf.jkt."""
        canonical = json.dumps(
            {"crv": self.jwk["crv"], "kty": self.jwk["kty"],
             "x": self.jwk["x"], "y": self.jwk["y"]},
            separators=(",", ":"), sort_keys=True,
        ).encode()
        return b64url(hashlib.sha256(canonical).digest())

    def sign(self, signing_input: bytes) -> bytes:
        """ES256: DER signature from the library, converted to the JOSE R||S form."""
        der = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def proof(self, htm: str, htu: str, jti: str = None, iat: int = None,
              access_token: str = None) -> str:
        """
        Build a DPoP proof JWT.

        jti and iat are explicit parameters so that a proof can be replayed verbatim:
        replay means presenting the same jti with the same iat, not a fresh proof.

        Pass jti=OMIT to leave the claim out entirely. An empty string is a distinct
        case: the claim is present but blank.
        """
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}
        payload = {
            "htm": htm,
            "htu": htu,
            "iat": iat if iat is not None else int(time.time()),
        }
        if jti is not OMIT:
            payload["jti"] = str(uuid.uuid4()) if jti is None else jti
        if access_token:
            payload["ath"] = b64url(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(payload, separators=(",", ":")).encode())
        ).encode("ascii")
        return signing_input.decode("ascii") + "." + b64url(self.sign(signing_input))


def fetch_token(token_endpoint: str, key: DPoPKey, client_id: str,
                username: str, password: str) -> dict:
    """
    Acquire a DPoP-bound access token via the direct grant.

    Returns the full token response so the caller can assert on token_type and
    inspect the cnf.jkt binding.
    """
    proof = key.proof("POST", token_endpoint)
    response = httpx.post(
        token_endpoint,
        data={
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": "openid",
        },
        headers={"DPoP": proof},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


def decode_claims(jwt_str: str) -> dict:
    """Decode JWT claims without verification. For asserting cnf.jkt only."""
    payload = jwt_str.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))
