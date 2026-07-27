"""
Correctness assertions for conditions C0 (bearer baseline) and M1 (RFC 8705
mutual-TLS certificate-bound access tokens).

Correctness only. No latency, no load, no capacity numbers. Every check prints
PASS or FAIL and the script exits non-zero if anything failed.

C0 is the control. It establishes that a bearer token is a pure bearer instrument:
whoever holds it can use it, from any TLS client identity or none. M1 is the
treatment. It establishes that the same request pattern fails once the token is
bound to a certificate.

References:
  RFC 8705 section 3    certificate-bound access tokens
  RFC 8705 section 3.1  cnf["x5t#S256"] is base64url(SHA-256(DER(certificate)))
  RFC 8705 section 2.1  tls_client_auth, the PKI client authentication method

Requires python3 with httpx.
"""

import base64
import hashlib
import os
import re
import ssl
import sys
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
CERTS = HERE.parent / "certs" / "generated"

CA = str(CERTS / "ca" / "ca.pem")
CLIENT_A = (str(CERTS / "clients" / "client-a.crt"), str(CERTS / "clients" / "client-a.key"))
CLIENT_B = (str(CERTS / "clients" / "client-b.crt"), str(CERTS / "clients" / "client-b.key"))

KEYCLOAK = os.environ.get("KEYCLOAK_BASE", "https://localhost:9443")
RS = os.environ.get("RS_BASE", "https://localhost:9444")

REALM = "mtls-demo"
TOKEN_ENDPOINT = f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token"
DISCOVERY = f"{KEYCLOAK}/realms/{REALM}/.well-known/openid-configuration"

RESOURCE = f"{RS}/api/resource"
BOUND = f"{RS}/api/bound"

TIMEOUT = 30.0

results = []


def record(name, expected, actual, note=""):
    ok = expected == actual
    status = "PASS" if ok else "FAIL"
    results.append((status, name, f"expected {expected}, got {actual}"))
    suffix = f"  ({note})" if note else ""
    print(f"  {status}  {name:58s} expected {expected!r}, got {actual!r}{suffix}")
    return ok


def info(name, value):
    print(f"  INFO  {name:58s} {value}")


def x5t_s256(cert_path):
    """RFC 8705 section 3.1: base64url(SHA-256(DER(cert))), no padding.

    Computed here from the PEM file rather than read from anything the cert
    generator wrote, so the assertion is independent of that script.
    """
    pem = Path(cert_path).read_text()
    body = re.findall(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S
    )[0]
    der = base64.b64decode("".join(body.split()))
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()


def claims(jwt_str):
    """Decode JWT claims without verifying. For inspecting cnf only."""
    import json

    payload = jwt_str.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def client(cert=None):
    """An httpx client pinned to the lab CA, optionally presenting a client cert.

    An explicit SSLContext rather than verify=<path> / cert=<tuple>: httpx 0.28
    deprecated both of those forms. Hostname verification stays on, which the
    server certificates satisfy through their DNS:localhost SAN.
    """
    ctx = ssl.create_default_context(cafile=CA)
    if cert is not None:
        ctx.load_cert_chain(certfile=cert[0], keyfile=cert[1])
    return httpx.Client(verify=ctx, timeout=TIMEOUT)


def get(url, token, cert=None):
    with client(cert) as c:
        return c.get(url, headers={"Authorization": f"Bearer {token}"})


def main():
    a_thumb = x5t_s256(CLIENT_A[0])
    b_thumb = x5t_s256(CLIENT_B[0])

    print("\nPKI under test")
    info("client-a x5t#S256 (expected binding)", a_thumb)
    info("client-b x5t#S256 (unbound peer)", b_thumb)
    record("the two client certificates are distinct", True, a_thumb != b_thumb)

    print("\nAuthorization server metadata")
    with client() as c:
        meta = c.get(DISCOVERY).json()
    # Keycloak hardcodes this to true in OIDCWellKnownProvider regardless of whether
    # mTLS is actually configured, so it is reported, not asserted. It is not evidence
    # that this deployment is correctly configured.
    info(
        "tls_client_certificate_bound_access_tokens (advertised)",
        meta.get("tls_client_certificate_bound_access_tokens"),
    )
    info(
        "tls_client_auth in token_endpoint_auth_methods_supported",
        "tls_client_auth" in (meta.get("token_endpoint_auth_methods_supported") or []),
    )

    # ---------------------------------------------------------------- C0 --

    print("\nC0  bearer baseline: token acquisition")
    with client() as c:
        r = c.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "password",
                "client_id": "bearer-client",
                "username": "testuser",
                "password": "testpass",
                "scope": "openid",
            },
        )
    record("bearer-client token request succeeds", 200, r.status_code, r.text[:120])
    if r.status_code != 200:
        print("\nCannot continue without a C0 token.")
        return 1
    body = r.json()
    c0_token = body["access_token"]
    record("token_type is Bearer", "Bearer", body.get("token_type"))
    c0_claims = claims(c0_token)
    record("C0 token carries no cnf claim", None, c0_claims.get("cnf"))

    print("\nC0  the token is a pure bearer instrument")
    # This is the threat that sender constraining exists to remove. All three must
    # succeed. A FAIL here means the control condition is not a control.
    record("accepted over client certificate A", 200,
           get(RESOURCE, c0_token, CLIENT_A).status_code)
    record("replayed over a different certificate B", 200,
           get(RESOURCE, c0_token, CLIENT_B).status_code,
           "no possession check")
    record("replayed with no client certificate at all", 200,
           get(RESOURCE, c0_token, None).status_code,
           "no possession check")

    print("\nC0  the resource server does validate something")
    record("garbage token rejected", 401,
           get(RESOURCE, "not.a.token", CLIENT_A).status_code)
    record("token with a tampered signature rejected", 401,
           get(RESOURCE, c0_token[:-4] + "AAAA", CLIENT_A).status_code)

    print("\nC0  unbound token at the binding-required endpoint")
    # Spring Security's X509CertificateThumbprintValidator returns success when the
    # token has no cnf claim. The default endpoint therefore admits a bearer token
    # over a connection with no client certificate. That is the silent binding
    # failure; /api/bound is the explicit guard.
    record("bearer token admitted by the default endpoint", 200,
           get(RESOURCE, c0_token, None).status_code,
           "Spring default fails open on absent cnf")
    record("bearer token rejected by /api/bound", 403,
           get(BOUND, c0_token, None).status_code)

    # ---------------------------------------------------------------- M1 --

    print("\nM1  tls_client_auth at the token endpoint (RFC 8705 section 2.1)")
    with client(CLIENT_A) as c:
        r = c.post(
            TOKEN_ENDPOINT,
            data={"grant_type": "client_credentials", "client_id": "mtls-client"},
        )
    record("mtls-client authenticates with certificate A", 200, r.status_code,
           r.text[:160])
    if r.status_code != 200:
        print("\nCannot continue without an M1 token.")
        return 1
    m1_token = r.json()["access_token"]

    with client(CLIENT_B) as c:
        r_b = c.post(
            TOKEN_ENDPOINT,
            data={"grant_type": "client_credentials", "client_id": "mtls-client"},
        )
    record("mtls-client rejected with certificate B", 401, r_b.status_code,
           "subject DN mismatch")

    with client() as c:
        r_none = c.post(
            TOKEN_ENDPOINT,
            data={"grant_type": "client_credentials", "client_id": "mtls-client"},
        )
    record("mtls-client rejected with no certificate", 401, r_none.status_code)

    print("\nM1  the token is certificate bound (RFC 8705 section 3.1)")
    m1_claims = claims(m1_token)
    cnf = m1_claims.get("cnf")
    record("access token carries a cnf claim", True, isinstance(cnf, dict))
    record("cnf contains x5t#S256", True,
           isinstance(cnf, dict) and "x5t#S256" in cnf)
    record("x5t#S256 equals base64url(SHA-256(DER(client-a)))", a_thumb,
           (cnf or {}).get("x5t#S256"))
    record("x5t#S256 is not the other certificate's thumbprint", False,
           (cnf or {}).get("x5t#S256") == b_thumb)

    print("\nM1  presentation to the resource server")
    record("accepted over the bound certificate A", 200,
           get(RESOURCE, m1_token, CLIENT_A).status_code)
    record("rejected over a different certificate B", 401,
           get(RESOURCE, m1_token, CLIENT_B).status_code,
           "thumbprint mismatch")
    record("rejected with no client certificate", 401,
           get(RESOURCE, m1_token, None).status_code,
           "no certificate to compare")

    print("\nM1  binding-required endpoint")
    record("accepted at /api/bound over certificate A", 200,
           get(BOUND, m1_token, CLIENT_A).status_code)
    record("rejected at /api/bound over certificate B", 401,
           get(BOUND, m1_token, CLIENT_B).status_code)
    r_bound = get(BOUND, m1_token, CLIENT_A)
    record("/api/bound echoes the bound thumbprint", a_thumb,
           r_bound.json().get("x5t#S256") if r_bound.status_code == 200 else None)

    # ----------------------------------------------------------------------

    passed = sum(1 for r in results if r[0] == "PASS")
    failed = sum(1 for r in results if r[0] == "FAIL")
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("\nFAILURES")
        for status, name, detail in results:
            if status == "FAIL":
                print(f"  {name}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    if not Path(CA).exists():
        print(f"Missing {CA}. Run certs/gen-certs.sh first.")
        sys.exit(2)
    sys.exit(main())
