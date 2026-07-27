package io.github.sergioemancinas.rs;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Single-node DPoP resource server left at Spring Security defaults.
 *
 * Nothing here customises the replay cache. DPoP support is auto-configured by
 * OAuth2ResourceServerConfigurer when DPoPProofJwtDecoderFactory is on the classpath,
 * which installs the default validator chain: htm, htu, JtiClaimValidator,
 * JwtIssuedAtValidator. JtiClaimValidator is backed by a static LinkedHashMap bounded at
 * MAX_SIZE = 1000 under an evict-eldest policy. That bound is the object under test.
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
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@RestController
	static class ProtectedResource {

		/**
		 * The endpoint under load. Deliberately trivial: the measurement concerns proof
		 * validation, not application work.
		 */
		@GetMapping("/api/resource")
		Map<String, String> resource() {
			return Map.of("status", "ok");
		}
	}
}
