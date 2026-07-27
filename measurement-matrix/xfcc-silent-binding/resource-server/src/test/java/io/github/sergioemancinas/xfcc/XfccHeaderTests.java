package io.github.sergioemancinas.xfcc;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for the XFCC parser and for the exact behaviour that separates X1 from X2.
 *
 * <p>Self-contained: the fixture certificate is embedded rather than read from
 * {@code pki/out/}, so this runs in the Docker build and in a bare checkout.
 */
class XfccHeaderTests {

	private static final String PEM = """
			-----BEGIN CERTIFICATE-----
			MIIB4DCCAYWgAwIBAgIUfCBwH/HG2dTYipCkUy4OCcCtUikwCgYIKoZIzj0EAwIw
			RzELMAkGA1UEBhMCWFgxITAfBgNVBAoMGG9hdXRoLXJlcGxheS1tZWFzdXJlbWVu
			dDEVMBMGA1UEAwwMeGZjYy1kZW1vLWNhMB4XDTIwMDEwMTAwMDAwMFoXDTM1MDEw
			MTAwMDAwMFowRjELMAkGA1UEBhMCWFgxITAfBgNVBAoMGG9hdXRoLXJlcGxheS1t
			ZWFzdXJlbWVudDEUMBIGA1UEAwwLY2xpZW50LWdvb2QwWTATBgcqhkjOPQIBBggq
			hkjOPQMBBwNCAARWR/a4+ROz/DUQxMNStXCnS1imNe0latR4q7B7ZT3nn1LcJUvh
			mCp5haYewAujxbDVuMxgR5xXZ7uWczav2yuho1AwTjAMBgNVHRMBAf8EAjAAMBMG
			A1UdJQQMMAoGCCsGAQUFBwMCMCkGA1UdEQQiMCCGHnNwaWZmZTovL3hmY2MtZGVt
			by9jbGllbnQtZ29vZDAKBggqhkjOPQQDAgNJADBGAiEA6eC1hFmmVHxqMlMWBO5b
			4MgvK5s9sP8v7eEW0ccAABMCIQD3cNiORAiJRzHhpG+ouPFh57kzOm3KUISJSKz4
			GqqW7A==
			-----END CERTIFICATE-----
			""";

	/** RFC 8705 section 3.1 confirmation value for the fixture, cross-checked against openssl. */
	private static final String EXPECTED_THUMBPRINT = "6G7KrHMEySNwTz-dneIeAeFGh2n4J2Wna7Bnt78jGXw";

	/** Envoy leaves ALPHA, DIGIT, '*', '-', '.' and '_' alone and percent-encodes the rest. */
	private static String envoyUrlEncode(String text) {
		StringBuilder out = new StringBuilder();
		for (char c : text.toCharArray()) {
			boolean unreserved = Character.isLetterOrDigit(c) && c < 128;
			unreserved |= (c == '*' || c == '-' || c == '.' || c == '_');
			out.append(unreserved ? String.valueOf(c) : String.format("%%%02X", (int) c));
		}
		return out.toString();
	}

	private static String envoyHeader() {
		// Subject is double-quoted and contains commas. A parser that splits the header
		// on ',' before honouring quotes truncates it and then finds no Cert field.
		return "By=spiffe://cluster/ns/default/sa/envoy;"
				+ "Hash=abc123;"
				+ "Subject=\"CN=client-good,O=oauth-replay-measurement,C=XX\";"
				+ "URI=spiffe://xfcc-demo/client-good;"
				+ "Cert=\"" + envoyUrlEncode(PEM) + "\"";
	}

	private static X509Certificate parse(String pem) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509")
			.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
	}

	@Test
	void quotedSubjectCommasDoNotSplitTheElement() {
		List<Map<String, String>> elements = XfccHeader.parse(envoyHeader());
		assertThat(elements).hasSize(1);
		assertThat(XfccHeader.firstValue(elements, "Subject"))
			.isEqualTo("CN=client-good,O=oauth-replay-measurement,C=XX");
	}

	@Test
	void keyLookupIsCaseInsensitive() {
		List<Map<String, String>> elements = XfccHeader.parse(envoyHeader());
		assertThat(XfccHeader.firstValue(elements, "cert"))
			.isEqualTo(XfccHeader.firstValue(elements, "Cert"));
	}

	@Test
	void multipleElementsAreKeptInWireOrder() {
		List<Map<String, String>> elements = XfccHeader.parse("Hash=aaa;Subject=\"one\",Hash=bbb;Subject=\"two\"");
		assertThat(elements).hasSize(2);
		assertThat(XfccHeader.firstValue(elements, "Hash")).isEqualTo("aaa");
	}

	@Test
	void percentDecodeRoundTripsEnvoyEncoding() {
		assertThat(XfccHeader.percentDecode(envoyUrlEncode(PEM))).isEqualTo(PEM);
	}

	/** X1: decode, then parse. This is what the encoding requires. */
	@Test
	void decodedCertParsesAndYieldsTheRfc8705Thumbprint() throws Exception {
		String cert = XfccHeader.firstValue(XfccHeader.parse(envoyHeader()), "Cert");
		X509Certificate x509 = parse(XfccHeader.percentDecode(cert));
		assertThat(x509.getSubjectX500Principal().getName()).contains("CN=client-good");
		assertThat(LenientCertificateBindingValidator.thumbprint(x509)).isEqualTo(EXPECTED_THUMBPRINT);
	}

	/**
	 * X2: skip the decode. The PEM armour arrives as {@code -----BEGIN%20CERTIFICATE-----}
	 * and the parse fails. The failure is deterministic and total; there is no partial
	 * or lenient parse to fall back on.
	 */
	@Test
	void undecodedCertDoesNotParse() {
		String cert = XfccHeader.firstValue(XfccHeader.parse(envoyHeader()), "Cert");
		assertThat(cert).startsWith("-----BEGIN%20CERTIFICATE-----%0A");
		// Assert the behaviour, not the JVM's wording. The message differs by JDK
		// ("Illegal header" on 25, "Incomplete data" on 21); what matters is that no
		// certificate is produced and the failure is total rather than partial.
		assertThatThrownBy(() -> parse(cert)).isInstanceOf(CertificateException.class);
	}

	@Test
	void missingCertFieldYieldsNull() {
		String header = "By=spiffe://cluster/envoy;Hash=abc123;"
				+ "Subject=\"CN=client-good,O=oauth-replay-measurement,C=XX\";"
				+ "DNS=client-good.example";
		assertThat(XfccHeader.firstValue(XfccHeader.parse(header), "Cert")).isNull();
	}

}
