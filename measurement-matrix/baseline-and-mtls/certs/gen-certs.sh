#!/usr/bin/env bash
#
# Generate the PKI for conditions C0 and M1.
#
# One self-signed CA signs everything: two TLS server certificates and two client
# certificates. RFC 8705 section 2.1 tls_client_auth is the PKI method, so client
# certificates must chain to a CA the authorization server trusts. A literally
# self-signed client certificate would be the section 2.2 self_signed_tls_client_auth
# method, which Keycloak does not implement.
#
# Output goes to certs/generated/, which is gitignored. Private keys are never
# committed. Re-running overwrites everything: the PKI is disposable.
#
# Requires openssl 1.1.1 or later (for -addext).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/generated"

DAYS="${CERT_DAYS:-825}"
KEYBITS=2048

# Single-RDN subjects, deliberately. Keycloak's X509ClientAuthenticator compares the
# configured x509.subjectdn against the certificate by canonicalising both through
# X500Principal.getName(RFC2253). RFC 2253 emits RDNs in reverse DER order, so a
# multi-RDN subject makes the string that must appear in the realm export depend on
# the encoder's ordering. One RDN removes that ambiguity entirely.
CA_SUBJ="/CN=oauth-replay-measurement-lab-ca"
KC_SUBJ="/CN=keycloak-mtls-lab"
RS_SUBJ="/CN=resource-server-mtls-lab"
CLIENT_A_SUBJ="/CN=mtls-client"
CLIENT_B_SUBJ="/CN=mtls-client-other"

rm -rf "$OUT"
mkdir -p "$OUT"/{ca,keycloak,resource-server,clients}

log() { printf '  %s\n' "$*"; }

# --- CA -----------------------------------------------------------------------

openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEYBITS" \
  -out "$OUT/ca/ca.key" 2>/dev/null

openssl req -x509 -new -key "$OUT/ca/ca.key" -sha256 -days "$DAYS" \
  -subj "$CA_SUBJ" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/ca/ca.pem" 2>/dev/null
log "CA                     $CA_SUBJ"

# --- helpers ------------------------------------------------------------------

# issue <dir> <name> <subject> <extended-key-usage> [subjectAltName]
issue() {
  local dir="$1" name="$2" subj="$3" eku="$4" san="${5:-}"
  local key="$OUT/$dir/$name.key" csr="$OUT/$dir/$name.csr" crt="$OUT/$dir/$name.crt"

  openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEYBITS" \
    -out "$key" 2>/dev/null
  openssl req -new -key "$key" -subj "$subj" -out "$csr" 2>/dev/null

  local extfile="$OUT/$name.ext"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=$eku"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid,issuer"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$extfile"

  openssl x509 -req -in "$csr" -CA "$OUT/ca/ca.pem" -CAkey "$OUT/ca/ca.key" \
    -CAcreateserial -days "$DAYS" -sha256 -extfile "$extfile" -out "$crt" 2>/dev/null

  rm -f "$csr" "$extfile"
  chmod 600 "$key"
}

# RFC 8705 section 3.1: base64url(SHA-256(DER(certificate))), no padding.
# Computed over the whole DER certificate, not the public key.
thumbprint() {
  openssl x509 -in "$1" -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A \
    | tr '+/' '-_' \
    | tr -d '='
}

# --- TLS server certificates --------------------------------------------------

# Both SANs matter: the host reaches these over localhost, containers reach each
# other over the compose service name.
issue keycloak kc "$KC_SUBJ" serverAuth \
  "DNS:localhost,DNS:keycloak,IP:127.0.0.1"
log "Keycloak TLS server    $KC_SUBJ"

issue resource-server rs "$RS_SUBJ" serverAuth \
  "DNS:localhost,DNS:resource-server,IP:127.0.0.1"
log "Resource server TLS    $RS_SUBJ"

# --- client certificates ------------------------------------------------------

# client-a is the certificate the M1 token is bound to.
issue clients client-a "$CLIENT_A_SUBJ" clientAuth
log "Client A (bound)       $CLIENT_A_SUBJ"

# client-b is a different, equally valid certificate from the same CA. It must
# pass the TLS handshake so that any rejection is attributable to RFC 8705
# section 3.1 token validation rather than to the transport refusing the peer.
issue clients client-b "$CLIENT_B_SUBJ" clientAuth
log "Client B (unbound)     $CLIENT_B_SUBJ"

# --- report -------------------------------------------------------------------

A_THUMB="$(thumbprint "$OUT/clients/client-a.crt")"
B_THUMB="$(thumbprint "$OUT/clients/client-b.crt")"

cat <<EOF

Expected RFC 8705 cnf.x5t#S256 values

  client-a  $A_THUMB
  client-b  $B_THUMB

A token issued to mtls-client over client-a must carry the first value.
test/assertions.py recomputes these independently; nothing is read from here.

Realm export must contain, for client mtls-client:
  "x509.subjectdn": "CN=mtls-client"
EOF
