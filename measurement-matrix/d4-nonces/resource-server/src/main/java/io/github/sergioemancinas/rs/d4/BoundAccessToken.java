package io.github.sergioemancinas.rs.d4;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2Token;

import java.time.Instant;
import java.util.Map;

/**
 * The authenticated access token plus its claims, in the shape the {@code ath} and
 * {@code cnf.jkt} validators need.
 *
 * <p>Spring Security has an identical private nested record in
 * {@code DPoPAuthenticationProvider}. It is not accessible, so it is restated here.
 */
record BoundAccessToken(OAuth2Token delegate, Map<String, Object> claims) implements OAuth2Token, ClaimAccessor {

	@Override
	public String getTokenValue() {
		return this.delegate.getTokenValue();
	}

	@Override
	public Instant getIssuedAt() {
		return this.delegate.getIssuedAt();
	}

	@Override
	public Instant getExpiresAt() {
		return this.delegate.getExpiresAt();
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

}
