"""
Access-token minting and XFCC primitives for conditions X1 and X2.

There is no authorization server in this stack. Tokens are minted here with the key
whose public half pki/generate_pki.py published as jwks.json. See the README section
"Why there is no Keycloak in this stack" for why that is the honest choice rather than
a shortcut.
"""

import base64
import hashlib
import json
import pathlib
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import load_pem_x509_certificate

PKI = pathlib.Path(__file__).resolve().parent.parent / "pki" / "out"

ISSUER = "https://xfcc-demo.invalid/issuer"
KID = "xfcc-demo-1"

# Envoy's Http::Utility::PercentEncoding::urlEncode leaves exactly these octets alone.
# Everything else becomes %XX with uppercase hex digits, and space becomes %20 rather
# than "+". Source: envoy source/common/http/utility.cc, urlEncode, and the contract
# documented on Utility::PercentEncoding in source/common/http/utility.h.
ENVOY_UNRESERVED = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "*-._"
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def certificate(name: str):
    return load_pem_x509_certificate((PKI / f"{name}.crt").read_bytes())


def der(name: str) -> bytes:
    return certificate(name).public_bytes(serialization.Encoding.DER)


def x5t_s256(name: str) -> str:
    """RFC 8705 section 3.1 confirmation value: base64url SHA-256 of the DER, unpadded."""
    return b64url(hashlib.sha256(der(name)).digest())


def envoy_hash(name: str) -> str:
    """
    The value Envoy puts in the XFCC Hash field.

    Envoy computes Hex::encode(SHA256(DER)) in
    ConnectionInfoImplBase::sha256PeerCertificateDigest. Same digest as x5t#S256,
    different encoding. An application that compares Hash to cnf.x5t#S256 directly
    always sees a mismatch even when the certificate is correct.
    """
    return hashlib.sha256(der(name)).hexdigest()


def envoy_url_encode(text: str) -> str:
    return "".join(c if c in ENVOY_UNRESERVED else f"%{ord(c):02X}" for c in text)


def envoy_xfcc_element(name: str) -> str:
    """Reconstruct the XFCC element Envoy emits for a given client certificate."""
    cert = certificate(name)
    pem = (PKI / f"{name}.crt").read_text()
    subject = cert.subject.rfc4514_string()
    return (
        f"Hash={envoy_hash(name)};"
        f'Subject="{subject}";'
        f'Cert="{envoy_url_encode(pem)}"'
    )


class TokenSigner:
    """ES256 signer over the key published in jwks.json."""

    def __init__(self):
        self.key = serialization.load_pem_private_key(
            (PKI / "token-signing.key").read_bytes(), password=None
        )
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise TypeError("token-signing.key is not an EC key")

    def _sign(self, signing_input: bytes) -> bytes:
        der_sig = self.key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def mint(self, *, bound_to: str | None, subject: str = "demo-user",
             lifetime: int = 600) -> str:
        """
        Mint an access token.

        bound_to is a client name from the PKI, or None for a plain bearer token with
        no cnf claim. The unbound case is not a control for sloppiness; RFC 8705
        section 3.1 only applies when the confirmation claim is present, and Spring
        Security's validator returns success when it is absent. That branch is itself
        exercised here.
        """
        now = int(time.time())
        header = {"alg": "ES256", "kid": KID, "typ": "JWT"}
        payload = {
            "iss": ISSUER,
            "sub": subject,
            "iat": now,
            "exp": now + lifetime,
            "jti": b64url(now.to_bytes(8, "big") + hashlib.sha256(
                f"{subject}:{bound_to}:{now}".encode()).digest()[:8]),
        }
        if bound_to is not None:
            payload["cnf"] = {"x5t#S256": x5t_s256(bound_to)}

        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(payload, separators=(",", ":")).encode())
        ).encode("ascii")
        return signing_input.decode("ascii") + "." + b64url(self._sign(signing_input))
