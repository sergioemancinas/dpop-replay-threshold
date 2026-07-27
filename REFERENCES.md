# References

Every external work this repository refers to, with a resolving link. The accompanying
paper carries the full bibliography; this file exists so that a reader of the code and docs
can resolve any reference without the paper.

## Standards and specifications

- **RFC 9449**. D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, D. Waite,
  "OAuth 2.0 Demonstrating Proof of Possession (DPoP)," Sep. 2023.
  <https://www.rfc-editor.org/rfc/rfc9449.html>
- **RFC 8705**. B. Campbell, J. Bradley, N. Sakimura, T. Lodderstedt, "OAuth 2.0
  Mutual-TLS Client Authentication and Certificate-Bound Access Tokens," Feb. 2020.
  <https://www.rfc-editor.org/rfc/rfc8705.html>
- **RFC 6750**. M. Jones, D. Hardt, "The OAuth 2.0 Authorization Framework: Bearer Token
  Usage," Oct. 2012. <https://www.rfc-editor.org/rfc/rfc6750.html>
- **RFC 7638**. M. Jones, N. Sakimura, "JSON Web Key (JWK) Thumbprint," Sep. 2015.
  <https://www.rfc-editor.org/rfc/rfc7638.html>
- **RFC 2253**. M. Wahl, S. Kille, T. Howes, "Lightweight Directory Access Protocol (v3):
  UTF-8 String Representation of Distinguished Names," Dec. 1997.
  <https://www.rfc-editor.org/rfc/rfc2253.html>
- **RFC 3339**. G. Klyne, C. Newman, "Date and Time on the Internet: Timestamps,"
  Jul. 2002. <https://www.rfc-editor.org/rfc/rfc3339.html>

## Disclosed defects

- **CVE-2024-10039 / GHSA-93ww-43rr-79v3**. "Keycloak mTLS Authentication Bypass via
  Reverse Proxy TLS Termination," published 2024-11-25, patched in Keycloak 26.0.6.
  <https://github.com/keycloak/keycloak/security/advisories/GHSA-93ww-43rr-79v3>
- **Spring Security issue #18120**. "DPoP JtiClaimValidator does not prevent replay attack
  on multi-node setup," opened 2025-10-31, closed as a duplicate of #16940.
  <https://github.com/spring-projects/spring-security/issues/18120>
- **Spring Security issue #16940**. "Add support dpop customization," the enhancement
  #18120 was closed against. <https://github.com/spring-projects/spring-security/issues/16940>
- **Spring Security issue #17178**. request to make the RFC 8705 resource-server API
  public. <https://github.com/spring-projects/spring-security/issues/17178>
- **Keycloak issue #39042**. "[DPoP] Implementing DPoP nonce," open and unmilestoned since
  2025-04-17. <https://github.com/keycloak/keycloak/issues/39042>

## Source under study

- **Spring Security**, tag 6.5.5. `JtiClaimValidator` and `JtiCache` (MAX_SIZE = 1000) in
  `DPoPProofJwtDecoderFactory.java`; `JwtIssuedAtValidator` (clockSkew = 60 s);
  `X509CertificateThumbprintValidator`; `JwkThumbprintValidator` in
  `DPoPAuthenticationProvider`.
  <https://github.com/spring-projects/spring-security/tree/6.5.5>
- **Keycloak 26.6.1.** <https://github.com/keycloak/keycloak/tree/26.6.1>

## Methods

- **Romano-Kromrey effect-size thresholds**. J. Romano, J. D. Kromrey, J. Coraggio,
  J. Skowronek, "Appropriate statistics for ordinal level data: Should we really be using
  t-test and Cohen's d for evaluating group differences on the NSSE and other surveys?,"
  Annual meeting of the Florida Association of Institutional Research, 2006.
  Used for the Cliff's delta magnitude labels in `measurement-matrix/analysis/`.
- **Maricq et al.**. A. Maricq, D. Duplyakin, I. Jimenez, C. Maltzahn, R. Stutsman,
  R. Ricci, "Taming Performance Variability," in *Proc. 13th USENIX Symp. Operating Systems
  Design and Implementation (OSDI '18)*, pp. 409–425, 2018.
  <https://www.usenix.org/conference/osdi18/presentation/maricq>

## Prior implementations consulted

- **ConductorOne/DPoP**. Go implementation of RFC 9449. Its in-memory `jti` store is
  TTL-based with no capacity bound (`pkg/dpop/jti.go`), a design contrast used in the paper.
  <https://github.com/ConductorOne/DPoP>
- **Curity mutual-tls-api-example**. RFC 8705 certificate-bound tokens with reverse-proxy
  TLS termination and `cnf` thumbprint verification.
  <https://github.com/curityio/mutual-tls-api-example>
- **ahus1/dpop-demo**. DPoP proof-of-concept with Keycloak; realm-configuration reference.
  <https://github.com/ahus1/dpop-demo>
- **thomasdarimont/keycloak-project-example**, **little-pinecone/keycloak-in-docker**. Compose and realm-import patterns. These are cited as prior art; the stacks here are
  original.
