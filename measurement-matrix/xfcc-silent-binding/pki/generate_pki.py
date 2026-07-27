#!/usr/bin/env python3
"""
Generate the PKI and token-signing material for conditions X1 and X2.

Everything lands in pki/out/, which is gitignored. Nothing here is secret; the
material exists only so the demonstration is self-contained and reproducible.

Design notes that matter for the experiment:

* client-good and client-bad are signed by the SAME CA. Envoy trusts both, so both
  complete the TLS handshake. The wrong-certificate case must therefore be rejected
  by the RFC 8705 confirmation check, not by the TLS layer. If the two clients had
  different issuers the demonstration would prove nothing about token binding.

* The access-token signing key is EC P-256 (ES256), matching the DPoP material in
  ../../single-host-validation/. The resource server must be told
  jws-algorithms: ES256, because Spring Boot's default is RS256 only.
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = pathlib.Path(__file__).resolve().parent / "out"

# Fixed validity window so regenerating produces comparable material. Ten years is
# long enough that a stale checkout still works and short enough to be obviously
# a test artefact.
NOT_BEFORE = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2035, 1, 1, tzinfo=dt.timezone.utc)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "oauth-replay-measurement"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def write(path: pathlib.Path, data: bytes, mode: int = 0o644) -> None:
    path.write_bytes(data)
    path.chmod(mode)


def write_key(path: pathlib.Path, key) -> None:
    write(path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), 0o600)


def write_cert(path: pathlib.Path, cert: x509.Certificate) -> None:
    write(path, cert.public_bytes(serialization.Encoding.PEM))


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = name("xfcc-demo-ca")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca_key, ca_cert, cn, *, server: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    eku = x509.ExtendedKeyUsage([
        x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1" if server else "1.3.6.1.5.5.7.3.2")
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(eku, critical=False)
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("envoy"),
            ]),
            critical=False,
        )
    else:
        # A URI SAN so Envoy's XFCC "URI=" field is populated. Not used by the
        # RFC 8705 check; present so the header looks like production traffic.
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(f"spiffe://xfcc-demo/{cn}"),
            ]),
            critical=False,
        )
    return key, builder.sign(ca_key, hashes.SHA256())


def thumbprint(cert: x509.Certificate) -> str:
    """RFC 8705 section 3.1: base64url-encoded SHA-256 of the DER encoding, unpadded."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return b64url(hashlib.sha256(der).digest())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="regenerate even if pki/out already exists")
    args = parser.parse_args()

    if OUT.exists() and not args.force:
        print(f"{OUT} already exists; pass --force to regenerate", file=sys.stderr)
        return 1

    OUT.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = make_ca()
    write_key(OUT / "ca.key", ca_key)
    write_cert(OUT / "ca.crt", ca_cert)

    server_key, server_cert = make_leaf(ca_key, ca_cert, "localhost", server=True)
    write_key(OUT / "server.key", server_key)
    write_cert(OUT / "server.crt", server_cert)

    manifest = {"clients": {}}
    for cn in ("client-good", "client-bad"):
        key, cert = make_leaf(ca_key, ca_cert, cn, server=False)
        write_key(OUT / f"{cn}.key", key)
        write_cert(OUT / f"{cn}.crt", cert)
        manifest["clients"][cn] = {
            "x5t#S256": thumbprint(cert),
            "sha256_der_hex": hashlib.sha256(
                cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest(),
            "subject": cert.subject.rfc4514_string(),
        }

    # Access-token signing key. The resource server sees only the JWKS.
    token_key = ec.generate_private_key(ec.SECP256R1())
    write_key(OUT / "token-signing.key", token_key)
    numbers = token_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "xfcc-demo-1",
        "alg": "ES256",
        "use": "sig",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }
    write(OUT / "jwks.json", json.dumps({"keys": [jwk]}, indent=2).encode() + b"\n")
    manifest["jwk_kid"] = jwk["kid"]

    write(OUT / "manifest.json", json.dumps(manifest, indent=2).encode() + b"\n")

    print(f"wrote PKI to {OUT}")
    for cn, info in manifest["clients"].items():
        print(f"  {cn:12s} x5t#S256={info['x5t#S256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
