package io.github.sergioemancinas.rs.d4;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Supplies the {@code DPoP-Nonce} response header required by RFC 9449 Sections 8, 8.2 and
 * 9.
 *
 * <p>Spring Security 6.5.5 never emits this header. Its {@code DPoPAuthenticationEntryPoint}
 * writes {@code WWW-Authenticate: DPoP error="...", algs="..."} and nothing else, and it is
 * a {@code private static final} nested class of the package-private
 * {@code DPoPAuthenticationConfigurer}, which exposes no setters, so it cannot be replaced
 * through the {@code oauth2ResourceServer} DSL. A filter is the only remaining seam.
 *
 * <p>The nonce is issued before the chain runs rather than after, so the header is set
 * while the response is guaranteed uncommitted. Issuing unconditionally is what RFC 9449
 * Section 8.2 describes as the efficient case: the successful response already carries the
 * nonce for the next request, so no extra round trip is needed. It also means the 401
 * challenge and the 200 rotation are the same code path.
 *
 * <p>Registered ahead of every other security filter so that the header is present on
 * responses produced by the framework's DPoP entry point.
 */
public final class DPoPNonceIssuingFilter extends OncePerRequestFilter {

	static final String DPOP_NONCE_HEADER = "DPoP-Nonce";

	private static final String DPOP_SCHEME = "DPoP";

	private final DPoPNonceStore nonceStore;

	public DPoPNonceIssuingFilter(DPoPNonceStore nonceStore) {
		this.nonceStore = nonceStore;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		issueNonce(request, response);
		chain.doFilter(request, response);
	}

	private void issueNonce(HttpServletRequest request, HttpServletResponse response) {
		String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (!StringUtils.startsWithIgnoreCase(authorization, DPOP_SCHEME)) {
			return;
		}
		List<String> proofs = Collections.list(request.getHeaders(DPOP_SCHEME));
		if (proofs.size() != 1) {
			return;
		}
		String jkt = DPoPProofKeys.thumbprintOfUnverifiedProof(proofs.get(0));
		if (jkt == null) {
			return;
		}
		if (response.containsHeader(DPOP_NONCE_HEADER)) {
			// RFC 9449 Section 8: "there MUST NOT be more than one DPoP-Nonce header".
			return;
		}
		response.setHeader(DPOP_NONCE_HEADER, this.nonceStore.issue(jkt));
		// RFC 9449 Section 8.2: responses carrying a nonce should not be cacheable.
		response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
		// RFC 9449 Section 8: browser clients cannot read the header otherwise.
		response.addHeader(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, DPOP_NONCE_HEADER);
	}

}
