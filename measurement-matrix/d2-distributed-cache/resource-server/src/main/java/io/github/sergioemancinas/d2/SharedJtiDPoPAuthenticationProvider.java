package io.github.sergioemancinas.d2;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationToken;
import org.springframework.util.Assert;

/**
 * Wraps Spring Security's {@code DPoPAuthenticationProvider} and adds the shared-cache
 * {@code jti} check on top of it.
 *
 * The provider wraps rather than replaces. {@code DPoPAuthenticationProvider} builds its
 * {@code ath} and {@code jkt} validators from private inner classes, so substituting the
 * whole validator chain would require reimplementing that security-critical library logic.
 * Wrapping runs the library's own validators unchanged and adds the shared-cache check
 * after them.
 */
final class SharedJtiDPoPAuthenticationProvider implements AuthenticationProvider {

	private final AuthenticationProvider delegate;

	private final JwtDecoderFactory<DPoPProofContext> sharedJtiVerifier;

	SharedJtiDPoPAuthenticationProvider(AuthenticationProvider delegate,
			JwtDecoderFactory<DPoPProofContext> sharedJtiVerifier) {
		Assert.notNull(delegate, "delegate cannot be null");
		Assert.notNull(sharedJtiVerifier, "sharedJtiVerifier cannot be null");
		this.delegate = delegate;
		this.sharedJtiVerifier = sharedJtiVerifier;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// Library validation first: htm, htu, iat, ath, jkt and the process-local jti cache
		// all stay in force and all keep their default behaviour. Running it first also
		// means the shared cache is only written for proofs that are otherwise valid, so an
		// unauthenticated caller cannot burn arbitrary jti entries in Redis.
		Authentication result = this.delegate.authenticate(authentication);

		DPoPAuthenticationToken token = (DPoPAuthenticationToken) authentication;
		DPoPProofContext context = DPoPProofContext.withDPoPProof(token.getDPoPProof())
			.method(token.getMethod())
			.targetUri(token.getResourceUri())
			.build();
		try {
			// Second decode, so the proof signature is verified twice per request. D2 here
			// is a correctness condition with no latency claim attached, and the cost buys
			// not having to fork the library's validator chain.
			this.sharedJtiVerifier.createDecoder(context).decode(context.getDPoPProof());
		}
		catch (JwtException ex) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF), ex);
		}
		return result;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return DPoPAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
