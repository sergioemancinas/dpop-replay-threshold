package io.github.sergioemancinas.xfcc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The propagation shim: turns Envoy's {@code x-forwarded-client-cert} header back into
 * the servlet container's client-certificate contract.
 *
 * <p>Spring Security's {@code X509CertificateThumbprintValidator} reads the client
 * certificate from the request attribute {@code jakarta.servlet.request.X509Certificate}
 * (see {@code X509CertificateThumbprintValidator.DefaultX509CertificateSupplier}). Tomcat
 * populates that attribute from its own TLS layer. When TLS terminates at a proxy there
 * is no TLS layer under Tomcat, so the attribute is absent and something has to put it
 * back. RFC 8705 section 6.5 says how that happens is out of scope. This class is the
 * consequence of that sentence.
 *
 * <p>Two behaviours are selectable, and they are the independent variable of conditions
 * X1 and X2:
 *
 * <ul>
 * <li>{@code xfcc.url-decode=true} (X1): percent-decode the {@code Cert} value before
 * parsing it, which is what Envoy's encoding requires.</li>
 * <li>{@code xfcc.url-decode=false} (X2): parse the {@code Cert} value as-is. The PEM
 * armour arrives as {@code -----BEGIN%20CERTIFICATE-----%0A...} and
 * {@code CertificateFactory} rejects it with {@code Illegal header}.</li>
 * </ul>
 *
 * <p>In both cases a parse failure is swallowed and the request continues. A shim that
 * threw would take down every request that reaches the application without a client
 * certificate, including health checks and any non-mTLS path, so swallowing is the common
 * engineering choice, and it is what makes the downstream failure quiet. What happens next
 * is decided by the binding policy, not by this class.
 */
public class XfccClientCertificateFilter extends OncePerRequestFilter {

	/** The servlet attribute Tomcat would populate if TLS had not been terminated upstream. */
	static final String X509_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

	/** Diagnostic only. Never consulted by any security decision. */
	static final String OUTCOME_ATTRIBUTE = "xfcc.propagation.outcome";

	private static final String HEADER = "x-forwarded-client-cert";

	private final Log logger = LogFactory.getLog(getClass());

	private final boolean urlDecode;

	public XfccClientCertificateFilter(boolean urlDecode) {
		this.urlDecode = urlDecode;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		request.setAttribute(OUTCOME_ATTRIBUTE, install(request));
		filterChain.doFilter(request, response);
	}

	private String install(HttpServletRequest request) {
		String header = request.getHeader(HEADER);
		if (header == null || header.isBlank()) {
			// Limb one of the failure class: the proxy propagated nothing at all.
			return "no-xfcc-header";
		}

		List<Map<String, String>> elements = XfccHeader.parse(header);
		String cert = XfccHeader.firstValue(elements, "Cert");
		if (cert == null || cert.isEmpty()) {
			// Limb one again, subtler: the header is present and carries Subject, URI,
			// DNS and Hash, but not the certificate. Envoy only includes Cert when
			// set_current_client_cert_details.cert is true.
			return "xfcc-without-cert-field";
		}

		String pem = this.urlDecode ? XfccHeader.percentDecode(cert) : cert;
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			X509Certificate x509 = (X509Certificate) factory
				.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
			request.setAttribute(X509_ATTRIBUTE, new X509Certificate[] { x509 });
			return "installed";
		}
		catch (Exception ex) {
			// Limb two: metadata arrived, in a form this application cannot parse.
			// Logged, not surfaced. The caller sees nothing.
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Could not parse XFCC Cert field: " + ex.getMessage());
			}
			return "cert-field-unparseable";
		}
	}

}
