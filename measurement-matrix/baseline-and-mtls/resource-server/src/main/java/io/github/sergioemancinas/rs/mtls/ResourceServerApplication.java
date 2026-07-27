package io.github.sergioemancinas.rs.mtls;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Resource server for conditions C0 (bearer baseline) and M1 (RFC 8705
 * certificate-bound access tokens).
 *
 * <p>The RFC 8705 section 3.1 check is not implemented here. Spring Security 6.5.5
 * already performs it: {@code NimbusJwtDecoder} defaults its validator to
 * {@code JwtValidators.createDefault()}, which includes the package-private
 * {@code org.springframework.security.oauth2.jwt.X509CertificateThumbprintValidator}.
 * That validator reads the peer certificate from the servlet request attribute
 * {@code jakarta.servlet.request.X509Certificate}, computes
 * base64url(SHA-256(DER)), and compares it against {@code cnf["x5t#S256"]}.
 * Spring Boot's {@code OAuth2ResourceServerJwtConfiguration} composes its own
 * validators on top of {@code createDefaultWithIssuer}, so the binding check
 * survives autoconfiguration.
 *
 * <p>Two consequences of that being Spring's default rather than our code:
 *
 * <ol>
 *   <li>There is no public API for it. The class, its constructor and its
 *       {@code Supplier<X509Certificate>} are all package-private, so the binding
 *       cannot be configured, only inherited. Replacing the decoder's validator with
 *       a hand-built {@code DelegatingOAuth2TokenValidator} silently removes it.
 *       This configuration therefore does not touch the validator chain.
 *   <li>It fails open. When a token carries no {@code cnf} claim at all, the
 *       validator returns success. A plain bearer token is accepted by an endpoint
 *       that a deployer believes is mTLS-protected. That is a silent binding failure,
 *       so it is asserted rather than patched: {@code /api/resource} is left at the
 *       default and exhibits it, {@code /api/bound} rejects it explicitly.
 * </ol>
 */
@SpringBootApplication
public class ResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerApplication.class, args);
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/actuator/health").permitAll()
				.anyRequest().authenticated())
			// Left at defaults on purpose. Anything that sets a custom jwtDecoder or
			// a custom OAuth2TokenValidator here would drop the thumbprint check.
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@RestController
	static class ProtectedResource {

		/**
		 * Default behaviour, unmodified. A certificate-bound token is admitted only
		 * over its bound certificate. A token with no {@code cnf} claim is admitted
		 * over any connection, including one with no client certificate.
		 */
		@GetMapping("/api/resource")
		Map<String, String> resource() {
			return Map.of("status", "ok");
		}

		/**
		 * Same token validation, plus an explicit requirement that the token actually
		 * be certificate-bound. This is the guard Spring Security does not provide.
		 * Returns 403 for a well-formed but unbound token, distinguishing "you are not
		 * sender-constrained" from the 401 that "your binding does not match" produces.
		 */
		@GetMapping("/api/bound")
		ResponseEntity<Map<String, String>> bound(@AuthenticationPrincipal Jwt jwt) {
			String thumbprint = null;
			if (jwt.getClaim("cnf") instanceof Map<?, ?> cnf
					&& cnf.get("x5t#S256") instanceof String value
					&& !value.isBlank()) {
				thumbprint = value;
			}
			if (thumbprint == null) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN)
					.body(Map.of("error", "not_certificate_bound"));
			}
			return ResponseEntity.ok(Map.of("status", "ok", "x5t#S256", thumbprint));
		}
	}
}
