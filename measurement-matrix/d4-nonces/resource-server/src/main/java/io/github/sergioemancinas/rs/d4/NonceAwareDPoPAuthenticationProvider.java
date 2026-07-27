package io.github.sergioemancinas.rs.d4;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationToken;
import org.springframework.util.Assert;

/**
 * DPoP authentication with the RFC 9449 Section 9 nonce check added.
 *
 * <p>This class exists because {@code DPoPAuthenticationProvider} in Spring Security 6.5.5
 * cannot be adapted:
 *
 * <ul>
 * <li>it is declared {@code public final}, so it cannot be subclassed;</li>
 * <li>{@code setDPoPProofVerifierFactory} replaces the entire validator chain, discarding
 * the {@code ath} and {@code cnf.jkt} checks, which are private (see
 * {@link RestatedDPoPValidators});</li>
 * <li>its {@code catch (JwtException)} block discards the {@link OAuth2Error} produced by
 * the validators and substitutes {@code new OAuth2Error(INVALID_DPOP_PROOF)}. A
 * {@code use_dpop_nonce} error code therefore never reaches the response, and RFC 9449
 * Section 9 error signalling is unreachable.</li>
 * </ul>
 *
 * <p>What is reused: {@code DPoPProofJwtDecoderFactory} for {@code typ}, {@code alg},
 * {@code jwk} and signature verification, and its
 * {@code DEFAULT_JWT_VALIDATOR_FACTORY} for {@code htm}, {@code htu}, {@code jti} and
 * {@code iat}. The {@code jti} cache and its {@code MAX_SIZE = 1000} bound are therefore
 * still in the path, unchanged.
 */
public final class NonceAwareDPoPAuthenticationProvider implements AuthenticationProvider {

	private final AuthenticationManager tokenAuthenticationManager;

	private final DPoPProofJwtDecoderFactory proofVerifierFactory;

	public NonceAwareDPoPAuthenticationProvider(AuthenticationManager tokenAuthenticationManager,
			DPoPNonceStore nonceStore) {
		Assert.notNull(tokenAuthenticationManager, "tokenAuthenticationManager cannot be null");
		Assert.notNull(nonceStore, "nonceStore cannot be null");
		this.tokenAuthenticationManager = tokenAuthenticationManager;
		this.proofVerifierFactory = new DPoPProofJwtDecoderFactory();
		this.proofVerifierFactory.setJwtValidatorFactory((context) -> {
			BoundAccessToken accessToken = context.getAccessToken();
			OAuth2TokenValidator<Jwt> libraryDefaults = DPoPProofJwtDecoderFactory.DEFAULT_JWT_VALIDATOR_FACTORY
				.apply(context);
			return new DelegatingOAuth2TokenValidator<>(libraryDefaults,
					RestatedDPoPValidators.accessTokenHash(accessToken),
					RestatedDPoPValidators.jwkThumbprint(accessToken), new NonceClaimValidator(nonceStore));
		});
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		DPoPAuthenticationToken request = (DPoPAuthenticationToken) authentication;

		Authentication accessTokenAuthentication = this.tokenAuthenticationManager
			.authenticate(new BearerTokenAuthenticationToken(request.getAccessToken()));
		if (!(accessTokenAuthentication instanceof AbstractOAuth2TokenAuthenticationToken<?> tokenAuthentication)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
					"Unable to authenticate the DPoP-bound access token.", null));
		}

		BoundAccessToken accessToken = new BoundAccessToken((OAuth2Token) tokenAuthentication.getToken(),
				tokenAuthentication.getTokenAttributes());
		DPoPProofContext context = DPoPProofContext.withDPoPProof(request.getDPoPProof())
			.accessToken(accessToken)
			.method(request.getMethod())
			.targetUri(request.getResourceUri())
			.build();

		try {
			this.proofVerifierFactory.createDecoder(context).decode(context.getDPoPProof());
		}
		catch (JwtException ex) {
			throw new OAuth2AuthenticationException(toError(ex), ex);
		}
		return accessTokenAuthentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return DPoPAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Preserves {@code use_dpop_nonce} instead of collapsing every proof failure to
	 * {@code invalid_dpop_proof}, so the framework's {@code DPoPAuthenticationEntryPoint}
	 * renders the RFC 9449 Section 9 challenge.
	 */
	private static OAuth2Error toError(JwtException ex) {
		if (ex instanceof JwtValidationException validationException) {
			for (OAuth2Error error : validationException.getErrors()) {
				if (NonceClaimValidator.USE_DPOP_NONCE.equals(error.getErrorCode())) {
					return error;
				}
			}
		}
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
	}

}
