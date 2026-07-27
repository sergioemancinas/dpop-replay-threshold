package io.github.sergioemancinas.xfcc;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Resource server for conditions X1 and X2.
 *
 * <p>Two independent switches, both read from configuration, both fixed for the lifetime
 * of a container:
 *
 * <ul>
 * <li>{@code xfcc.url-decode}: whether the propagation shim percent-decodes Envoy's
 * {@code Cert} field before parsing it. X1 is {@code true}, X2 is {@code false}.</li>
 * <li>{@code xfcc.binding-policy}: {@code strict} leaves Spring Boot to autoconfigure the
 * decoder, which installs Spring Security's own fail-closed
 * {@code X509CertificateThumbprintValidator}. {@code lenient} replaces the decoder with
 * one whose chain skips the confirmation check when no certificate is available.</li>
 * </ul>
 *
 * <p>Crossing the two gives four cells. Nothing else differs between containers.
 */
@SpringBootApplication
public class XfccResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(XfccResourceServerApplication.class, args);
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.csrf((csrf) -> csrf.disable())
			.authorizeHttpRequests((auth) -> auth
				.requestMatchers("/actuator/health").permitAll()
				.anyRequest().authenticated())
			.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

	/**
	 * The shim runs ahead of the Spring Security filter chain, which sits at
	 * {@link SecurityProperties#DEFAULT_FILTER_ORDER}. It must also run after Spring
	 * Boot's {@code OrderedRequestContextFilter}
	 * ({@code REQUEST_WRAPPER_FILTER_MAX_ORDER - 105}), because the shipped validator
	 * reaches the request through {@code RequestContextHolder}. Ordering the shim at
	 * {@code DEFAULT_FILTER_ORDER - 1} satisfies both.
	 */
	@Bean
	FilterRegistrationBean<XfccClientCertificateFilter> xfccFilter(
			@Value("${xfcc.url-decode:true}") boolean urlDecode) {
		FilterRegistrationBean<XfccClientCertificateFilter> registration =
				new FilterRegistrationBean<>(new XfccClientCertificateFilter(urlDecode));
		registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 1);
		return registration;
	}

	/**
	 * Present only when {@code xfcc.binding-policy=lenient}. Defining a {@link JwtDecoder}
	 * bean makes Spring Boot's {@code JwtDecoderConfiguration} back off in its entirety
	 * ({@code @ConditionalOnMissingBean(JwtDecoder.class)}), which is what removes the
	 * shipped {@code X509CertificateThumbprintValidator} from the chain.
	 *
	 * <p>Hand-building a validator chain, rather than going
	 * through {@code JwtValidators.createDefaultWithValidators}, drops the RFC 8705 check
	 * with no warning. That is a second, configuration-level instance of the same failure
	 * class and it needs no proxy at all.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(name = "xfcc.binding-policy", havingValue = "lenient")
	static class LenientBindingConfiguration {

		@Bean
		JwtDecoder jwtDecoder(
				@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
				@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
			NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
				.jwsAlgorithm(SignatureAlgorithm.ES256)
				.build();
			decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
					new JwtTimestampValidator(),
					new JwtIssuerValidator(issuerUri),
					new LenientCertificateBindingValidator()));
			return decoder;
		}

	}

	/**
	 * The protected resource.
	 *
	 * <p>The body reports what the shim and the binding check saw. Those fields are
	 * diagnostics for the test harness. Every assertion in {@code test/test_xfcc.py} is
	 * made on the HTTP status code, never on this body, so a bug in the diagnostics
	 * cannot turn a failing assertion into a passing one.
	 */
	@RestController
	static class ProtectedResource {

		private final String urlDecode;

		private final String bindingPolicy;

		ProtectedResource(@Value("${xfcc.url-decode:true}") String urlDecode,
				@Value("${xfcc.binding-policy:strict}") String bindingPolicy) {
			this.urlDecode = urlDecode;
			this.bindingPolicy = bindingPolicy;
		}

		@GetMapping("/api/resource")
		Map<String, Object> resource(HttpServletRequest request, @AuthenticationPrincipal Jwt jwt) {
			Map<String, Object> body = new LinkedHashMap<>();
			body.put("status", "ok");
			body.put("xfcc_url_decode", this.urlDecode);
			body.put("binding_policy", this.bindingPolicy);
			body.put("propagation_outcome",
					String.valueOf(request.getAttribute(XfccClientCertificateFilter.OUTCOME_ATTRIBUTE)));

			Map<String, Object> cnf = (jwt != null) ? jwt.getClaim("cnf") : null;
			body.put("token_x5t_s256", (cnf != null) ? cnf.get("x5t#S256") : null);

			X509Certificate certificate = LenientCertificateBindingValidator.currentCertificate();
			String presented = null;
			if (certificate != null) {
				try {
					presented = LenientCertificateBindingValidator.thumbprint(certificate);
				}
				catch (Exception ex) {
					presented = "error";
				}
			}
			body.put("presented_x5t_s256", presented);
			return body;
		}

	}

}
