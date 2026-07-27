#!/usr/bin/env python3
"""
Conditions X1 and X2: certificate-binding propagation across a TLS-terminating proxy.

Prints PASS or FAIL per assertion and exits non-zero if any assertion fails or any
assertion could not be evaluated. Nothing is written to disk. There is no results
directory in this condition and there should not be one until the suite has actually
been run against a live stack.

Two groups:

  --local   invariants that need no containers: RFC 8705 section 3.1 thumbprint
            semantics, Envoy's encodings, and the parse behaviour that X2 turns on.
            Cross-checked against the openssl binary where an independent oracle
            exists.

  default   the above, then the eight-cell integration matrix over the running stack.

Every integration assertion is made on the HTTP status code. The JSON body carries
diagnostics and is printed, never asserted on, so a defect in the diagnostics cannot
convert a failing assertion into a passing one.
"""

import argparse
import base64
import json
import pathlib
import subprocess
import sys

import httpx

import tokens

PKI = tokens.PKI
COMPLETE = "https://localhost:18443"   # Envoy listener A: Cert and Chain propagated
LOSSY = "https://localhost:18444"      # Envoy listener B: Subject, URI, DNS only


class Report:

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errored = 0

    @staticmethod
    def _short(value, limit=72):
        text = repr(value)
        return text if len(text) <= limit else text[:limit - 3] + "..."

    def check(self, name, actual, expected, note=""):
        ok = actual == expected
        if ok:
            self.passed += 1
            mark = "PASS"
        else:
            self.failed += 1
            mark = "FAIL"
        detail = f"expected {self._short(expected)}, got {self._short(actual)}"
        print(f"  [{mark}] {name}: {detail}" + (f"  ({note})" if note else ""))
        return ok

    def error(self, name, message):
        self.errored += 1
        print(f"  [ERROR] {name}: {message}")

    def summary(self):
        print()
        print(f"{self.passed} passed, {self.failed} failed, {self.errored} errored")
        return 0 if (self.failed == 0 and self.errored == 0) else 1


def require_pki():
    if not (PKI / "manifest.json").exists():
        print(f"PKI missing. Run: python3 {PKI.parent / 'generate_pki.py'}", file=sys.stderr)
        raise SystemExit(2)


# ----------------------------------------------------------------------------------
# Local invariants
# ----------------------------------------------------------------------------------

def local_checks(report: Report) -> None:
    print("Local invariants (no containers required)")

    # RFC 8705 section 3.1 defines the confirmation value as the base64url-encoded
    # SHA-256 hash of the DER encoding of the certificate, with trailing padding
    # omitted. openssl's -fingerprint -sha256 is the same digest over the same bytes,
    # printed as colon-separated hex, so it is an independent oracle for the digest.
    for name in ("client-good", "client-bad"):
        try:
            out = subprocess.run(
                ["openssl", "x509", "-in", str(PKI / f"{name}.crt"),
                 "-noout", "-fingerprint", "-sha256"],
                capture_output=True, text=True, check=True,
            ).stdout
            hex_digest = out.split("=", 1)[1].strip().replace(":", "").lower()
        except Exception as exc:  # openssl absent or failed
            report.error(f"openssl oracle for {name}", str(exc))
            continue
        from_openssl = base64.urlsafe_b64encode(bytes.fromhex(hex_digest)).rstrip(b"=").decode()
        report.check(f"x5t#S256 of {name} matches openssl SHA-256 of the DER",
                     tokens.x5t_s256(name), from_openssl)

    # Envoy's XFCC Hash field is the same digest in lowercase hex. An application that
    # compares it to cnf.x5t#S256 without re-encoding never matches.
    good_hex = tokens.envoy_hash("client-good")
    report.check("Envoy Hash is hex of the same digest as x5t#S256",
                 base64.urlsafe_b64encode(bytes.fromhex(good_hex)).rstrip(b"=").decode(),
                 tokens.x5t_s256("client-good"))
    report.check("Envoy Hash is not byte-identical to x5t#S256",
                 good_hex == tokens.x5t_s256("client-good"), False,
                 "hex versus base64url, so a naive string compare always fails")

    # The encoding X2 mishandles.
    pem = (PKI / "client-good.crt").read_text()
    encoded = tokens.envoy_url_encode(pem)
    report.check("Envoy percent-encoding round-trips",
                 percent_decode(encoded), pem)
    report.check("undecoded XFCC Cert has no usable PEM header",
                 "-----BEGIN CERTIFICATE-----" in encoded, False,
                 "the armour arrives as -----BEGIN%20CERTIFICATE-----%0A")
    report.check("encoded form contains the mangled header",
                 encoded.startswith("-----BEGIN%20CERTIFICATE-----%0A"), True)

    # Sanity on the material itself: the two clients must differ, or the wrong
    # certificate case proves nothing.
    report.check("client-good and client-bad have different thumbprints",
                 tokens.x5t_s256("client-good") != tokens.x5t_s256("client-bad"), True)

    manifest = json.loads((PKI / "manifest.json").read_text())
    report.check("manifest thumbprint agrees with recomputation",
                 manifest["clients"]["client-good"]["x5t#S256"],
                 tokens.x5t_s256("client-good"))
    print()


def percent_decode(value: str) -> str:
    out = []
    i = 0
    while i < len(value):
        if value[i] == "%" and i + 2 < len(value):
            try:
                out.append(chr(int(value[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(value[i])
        i += 1
    return "".join(out)


# ----------------------------------------------------------------------------------
# Integration matrix
# ----------------------------------------------------------------------------------

def client_for(name: str | None) -> httpx.Client:
    kwargs = {"verify": str(PKI / "ca.crt"), "timeout": 15.0}
    if name is not None:
        kwargs["cert"] = (str(PKI / f"{name}.crt"), str(PKI / f"{name}.key"))
    return httpx.Client(**kwargs)


def call(client: httpx.Client, base: str, cell: str, token: str,
         extra_headers: dict | None = None):
    headers = {"Authorization": f"Bearer {token}"}
    if extra_headers:
        headers.update(extra_headers)
    return client.get(f"{base}/{cell}/api/resource", headers=headers)


def describe(response: httpx.Response) -> str:
    if response.status_code != 200:
        return response.headers.get("www-authenticate", "")[:160]
    try:
        body = response.json()
    except Exception:
        return ""
    return (f"propagation={body.get('propagation_outcome')} "
            f"token={body.get('token_x5t_s256')} "
            f"presented={body.get('presented_x5t_s256')}")


def integration_checks(report: Report) -> None:
    signer = tokens.TokenSigner()
    bound = signer.mint(bound_to="client-good")
    unbound = signer.mint(bound_to=None)

    print("Preconditions")
    # require_client_certificate is set on both listeners, so a connection presenting
    # no client certificate must not reach the application at all. If this passes for
    # the wrong reason, for instance because Envoy is not running, the cell matrix
    # below errors rather than passes.
    with client_for(None) as anonymous:
        try:
            response = anonymous.get(f"{COMPLETE}/x1-strict/api/resource")
            report.check("Envoy refuses a connection with no client certificate",
                         f"reached application, HTTP {response.status_code}",
                         "connection refused at TLS")
        except Exception as exc:
            report.check("Envoy refuses a connection with no client certificate",
                         "connection refused at TLS", "connection refused at TLS",
                         type(exc).__name__)

    with client_for("client-good") as good:
        try:
            response = good.get(f"{COMPLETE}/x1-strict/api/resource")
            report.check("no token is rejected", response.status_code, 401)
        except Exception as exc:
            report.error("no token is rejected", str(exc))
    print()

    # Cell matrix over listener A, complete propagation.
    #
    # X1 rows: the shim percent-decodes, so the certificate reaches the confirmation
    # check and RFC 8705 section 3.1 is enforced under both policies.
    # X2 rows: the shim does not percent-decode, the PEM will not parse, and the two
    # policies diverge. strict refuses everything. lenient admits everything.
    matrix = [
        ("X1 strict  legit certificate accepted",      COMPLETE, "x1-strict",  "client-good", bound, 200),
        ("X1 strict  wrong certificate rejected",      COMPLETE, "x1-strict",  "client-bad",  bound, 401),
        ("X1 lenient legit certificate accepted",      COMPLETE, "x1-lenient", "client-good", bound, 200),
        ("X1 lenient wrong certificate rejected",      COMPLETE, "x1-lenient", "client-bad",  bound, 401),
        ("X2 strict  legit certificate rejected",      COMPLETE, "x2-strict",  "client-good", bound, 401),
        ("X2 strict  wrong certificate rejected",      COMPLETE, "x2-strict",  "client-bad",  bound, 401),
        ("X2 lenient legit certificate accepted",      COMPLETE, "x2-lenient", "client-good", bound, 200),
        ("X2 lenient WRONG certificate also accepted", COMPLETE, "x2-lenient", "client-bad",  bound, 200),
    ]

    print("Listener A, complete propagation (Cert and Chain present)")
    for label, base, cell, cert, token, expected in matrix:
        try:
            with client_for(cert) as client:
                response = call(client, base, cell, token)
            report.check(label, response.status_code, expected, describe(response))
        except Exception as exc:
            report.error(label, f"{type(exc).__name__}: {exc}")
    print()

    print("Listener B, lossy propagation (Subject, URI, DNS only; no Cert)")
    lossy = [
        ("B strict  legit certificate rejected",       LOSSY, "x1-strict",  "client-good", bound, 401),
        ("B lenient legit certificate accepted",       LOSSY, "x1-lenient", "client-good", bound, 200),
        ("B lenient WRONG certificate also accepted",  LOSSY, "x1-lenient", "client-bad",  bound, 200),
    ]
    for label, base, cell, cert, token, expected in lossy:
        try:
            with client_for(cert) as client:
                response = call(client, base, cell, token)
            report.check(label, response.status_code, expected, describe(response))
        except Exception as exc:
            report.error(label, f"{type(exc).__name__}: {exc}")
    print()

    print("Confirmation semantics and header trust")
    extras = [
        # RFC 8705 section 3.1 governs tokens that carry the confirmation claim. A token
        # without one is an ordinary bearer token and the validator does not engage.
        # This is specified behaviour, not a defect, but it is the quietest failure in
        # the whole class: if the authorization server never bound the token, nothing
        # downstream ever says so.
        ("unbound token accepted under X1 strict",
         COMPLETE, "x1-strict", "client-good", unbound, 200, None),

        # CVE-2024-10039 is the case where the application trusts client-supplied
        # certificate metadata. Envoy's SANITIZE_SET discards any inbound XFCC before
        # setting its own, so presenting client-bad while forging a header that claims
        # client-good must still be rejected.
        ("forged XFCC header ignored under X1 strict",
         COMPLETE, "x1-strict", "client-bad", bound, 401,
         {"x-forwarded-client-cert": tokens.envoy_xfcc_element("client-good")}),

        ("forged XFCC header ignored under X1 lenient",
         COMPLETE, "x1-lenient", "client-bad", bound, 401,
         {"x-forwarded-client-cert": tokens.envoy_xfcc_element("client-good")}),
    ]
    for label, base, cell, cert, token, expected, headers in extras:
        try:
            with client_for(cert) as client:
                response = call(client, base, cell, token, headers)
            report.check(label, response.status_code, expected, describe(response))
        except Exception as exc:
            report.error(label, f"{type(exc).__name__}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--local", action="store_true",
                        help="run only the invariants that need no running stack")
    args = parser.parse_args()

    require_pki()
    report = Report()
    local_checks(report)
    if not args.local:
        integration_checks(report)
    return report.summary()


if __name__ == "__main__":
    raise SystemExit(main())
