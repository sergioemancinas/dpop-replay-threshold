package io.github.sergioemancinas.rs.d4;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import java.util.Map;

/**
 * Thumbprint helpers shared by the nonce validator and the nonce-issuing filter.
 *
 * <p>Spring Security computes the same value inside a private nested class of
 * {@code DPoPAuthenticationProvider}, which is not reachable from application code.
 */
final class DPoPProofKeys {

	private DPoPProofKeys() {
	}

	/**
	 * RFC 7638 SHA-256 thumbprint of the {@code jwk} JOSE header of an already decoded
	 * proof. Returns {@code null} if the header is absent or unparseable.
	 */
	@SuppressWarnings("unchecked")
	static String thumbprintOfDecodedProof(Map<String, Object> headers) {
		Object jwkHeader = headers.get("jwk");
		if (!(jwkHeader instanceof Map)) {
			return null;
		}
		return thumbprint((Map<String, Object>) jwkHeader);
	}

	/**
	 * RFC 7638 SHA-256 thumbprint of the {@code jwk} JOSE header of a serialised proof,
	 * parsed <em>without</em> verifying the signature. Only used to decide which key a
	 * newly issued nonce is bound to; see {@link DPoPNonceStore#issue(String)}.
	 */
	static String thumbprintOfUnverifiedProof(String serialisedProof) {
		try {
			JWK jwk = SignedJWT.parse(serialisedProof).getHeader().getJWK();
			return (jwk != null) ? jwk.computeThumbprint().toString() : null;
		}
		catch (Exception ex) {
			return null;
		}
	}

	private static String thumbprint(Map<String, Object> jwkJson) {
		try {
			return JWK.parse(jwkJson).computeThumbprint().toString();
		}
		catch (Exception ex) {
			return null;
		}
	}

}
