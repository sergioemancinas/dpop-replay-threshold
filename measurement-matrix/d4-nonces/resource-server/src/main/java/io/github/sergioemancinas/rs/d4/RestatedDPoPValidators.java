package io.github.sergioemancinas.rs.d4;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

/**
 * RFC 9449 Section 4.3 step 12, restated.
 *
 * <p>These two checks exist in Spring Security 6.5.5 but only as {@code private static
 * final} nested classes of {@code DPoPAuthenticationProvider}. The only public extension
 * point for the proof validator chain,
 * {@code DPoPProofJwtDecoderFactory.setJwtValidatorFactory}, <em>replaces</em> the whole
 * chain. {@code DPoPProofJwtDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY} is public but
 * covers only {@code htm}, {@code htu}, {@code jti} and {@code iat}.
 *
 * <p>Consequence: adding one validator to the chain forces an implementer to restate the
 * two security-critical checks that actually bind the proof to the access token. That is
 * the cost being documented, not a capability of the library.
 */
final class RestatedDPoPValidators {

	private RestatedDPoPValidators() {
	}

	/** RFC 9449 Section 4.3 step 12, first bullet: {@code ath} is the hash of the token. */
	static OAuth2TokenValidator<Jwt> accessTokenHash(BoundAccessToken accessToken) {
		return (proof) -> {
			String athClaim = proof.getClaimAsString("ath");
			if (!StringUtils.hasText(athClaim)) {
				return invalidProof("ath claim is required.");
			}
			String expected;
			try {
				expected = sha256Base64Url(accessToken.getTokenValue());
			}
			catch (Exception ex) {
				return invalidProof("Failed to compute SHA-256 thumbprint for access token.");
			}
			return athClaim.equals(expected) ? OAuth2TokenValidatorResult.success()
					: invalidProof("ath claim is invalid.");
		};
	}

	/**
	 * RFC 9449 Section 4.3 step 12, second bullet: the proof key is the key the access
	 * token is bound to via {@code cnf.jkt}.
	 */
	static OAuth2TokenValidator<Jwt> jwkThumbprint(BoundAccessToken accessToken) {
		return (proof) -> {
			Map<String, Object> cnf = accessToken.getClaimAsMap("cnf");
			if (CollectionUtils.isEmpty(cnf) || !(cnf.get("jkt") instanceof String jktClaim)) {
				return invalidProof("jkt claim is required.");
			}
			String proofThumbprint = DPoPProofKeys.thumbprintOfDecodedProof(proof.getHeaders());
			if (proofThumbprint == null) {
				return invalidProof("jwk header is missing or invalid.");
			}
			return jktClaim.equals(proofThumbprint) ? OAuth2TokenValidatorResult.success()
					: invalidProof("jkt claim is invalid.");
		};
	}

	private static OAuth2TokenValidatorResult invalidProof(String description) {
		return OAuth2TokenValidatorResult
			.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, description, null));
	}

	private static String sha256Base64Url(String value) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
