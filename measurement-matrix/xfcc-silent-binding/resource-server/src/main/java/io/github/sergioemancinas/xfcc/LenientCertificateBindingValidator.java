package io.github.sergioemancinas.xfcc;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * RFC 8705 section 3.1 confirmation check with one line changed.
 *
 * <p>Spring Security ships this check as the package-private
 * {@code org.springframework.security.oauth2.jwt.X509CertificateThumbprintValidator}, and
 * wires it into every decoder built through {@code JwtValidators.createDefault*}, which
 * is every decoder Spring Boot autoconfigures. That validator fails closed: if the
 * {@code cnf.x5t#S256} claim is present and no certificate can be obtained, it returns
 * {@code invalid_token} with the description "Unable to obtain X509Certificate from
 * current request."
 *
 * <p>This class is identical except for {@link #NO_CERTIFICATE_AVAILABLE}. When no
 * certificate is available it returns success instead of failure. That single
 * substitution is the difference between an outage and a silent loss of sender
 * constraining, and it is the shape that appears in deployments, because fail-closed
 * behaviour breaks every request path that legitimately has no client certificate and
 * the quickest way to make the outage stop is to stop failing.
 *
 * <p>This class is application code written for the demonstration. It is not, and does
 * not claim to be, a defect in Spring Security. Spring Security's own implementation
 * fails closed. See the README section "What this does not prove".
 */
class LenientCertificateBindingValidator implements OAuth2TokenValidator<Jwt> {

	/**
	 * The mutation under study. Flipping this to {@code false} reproduces Spring
	 * Security's shipped behaviour.
	 */
	private static final boolean NO_CERTIFICATE_AVAILABLE = true;

	private final Log logger = LogFactory.getLog(getClass());

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Map<String, Object> cnf = jwt.getClaim("cnf");
		String claimed = (cnf != null && cnf.get("x5t#S256") instanceof String value) ? value : null;
		if (claimed == null) {
			// Same as the shipped validator: a token that is not certificate-bound is
			// not this validator's business. This branch is itself a silent
			// path, one level up: if the authorization server never managed to bind the
			// token, nothing downstream complains.
			return OAuth2TokenValidatorResult.success();
		}

		X509Certificate certificate = currentCertificate();
		if (certificate == null) {
			if (NO_CERTIFICATE_AVAILABLE) {
				this.logger.debug("No client certificate available; skipping x5t#S256 check");
				return OAuth2TokenValidatorResult.success();
			}
			return failure("Unable to obtain X509Certificate from current request.");
		}

		String presented;
		try {
			presented = thumbprint(certificate);
		}
		catch (Exception ex) {
			return failure("Failed to compute SHA-256 Thumbprint for X509Certificate.");
		}

		if (!presented.equals(claimed)) {
			return failure("Invalid SHA-256 Thumbprint for X509Certificate.");
		}
		return OAuth2TokenValidatorResult.success();
	}

	private OAuth2TokenValidatorResult failure(String description) {
		return OAuth2TokenValidatorResult
			.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, null));
	}

	/**
	 * RFC 8705 section 3.1: base64url-encoded SHA-256 hash of the DER encoding of the
	 * X.509 certificate, with trailing padding omitted.
	 */
	static String thumbprint(X509Certificate certificate) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest(certificate.getEncoded()));
	}

	static X509Certificate currentCertificate() {
		RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
		if (attributes == null) {
			return null;
		}
		X509Certificate[] chain = (X509Certificate[]) attributes
			.getAttribute(XfccClientCertificateFilter.X509_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
		return (chain != null && chain.length > 0) ? chain[0] : null;
	}

}
