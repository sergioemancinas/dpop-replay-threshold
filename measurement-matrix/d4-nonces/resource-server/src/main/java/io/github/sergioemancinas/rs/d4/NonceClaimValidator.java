package io.github.sergioemancinas.rs.d4;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * RFC 9449 Section 4.3 step 10: the {@code nonce} claim must match a nonce the server
 * supplied to this client.
 *
 * <p>This validator has no counterpart in Spring Security 6.5.5. The library's default
 * chain is {@code htm}, {@code htu}, {@code jti}, {@code iat} only.
 *
 * <p>The nonce is always required, which satisfies RFC 9449 Section 11.3 ("A server MUST
 * NOT accept any DPoP proofs without the nonce claim when a DPoP nonce has been provided
 * to the client") for a deployment that supplies a nonce on every response.
 */
final class NonceClaimValidator implements OAuth2TokenValidator<Jwt> {

	/**
	 * RFC 9449 Sections 8 and 9. Not present in
	 * {@code org.springframework.security.oauth2.core.OAuth2ErrorCodes}, which defines
	 * {@code invalid_dpop_proof} and nothing else for DPoP.
	 */
	static final String USE_DPOP_NONCE = "use_dpop_nonce";

	private final DPoPNonceStore nonceStore;

	NonceClaimValidator(DPoPNonceStore nonceStore) {
		this.nonceStore = nonceStore;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt proof) {
		String nonce = proof.getClaimAsString("nonce");
		if (!StringUtils.hasText(nonce)) {
			return failure("Resource server requires nonce in DPoP proof");
		}
		String jkt = DPoPProofKeys.thumbprintOfDecodedProof(proof.getHeaders());
		if (jkt == null) {
			return failure("jwk header is missing or invalid");
		}
		if (!this.nonceStore.consume(nonce, jkt)) {
			// Unknown, expired, already spent, or bound to a different key. RFC 9449
			// Section 8 uses the same error code for a missing nonce and a nonce
			// mismatch, and the response carries a fresh nonce either way.
			return failure("nonce claim is invalid");
		}
		return OAuth2TokenValidatorResult.success();
	}

	private static OAuth2TokenValidatorResult failure(String description) {
		return OAuth2TokenValidatorResult.failure(new OAuth2Error(USE_DPOP_NONCE, description, null));
	}

}
