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
 * Single-node DPoP resource server left at Spring Security 7.1.2 defaults.
 *
 * Identical to the 6.5.5 server in single-host-validation/; only the library differs.
 * Nothing here customises the replay cache. The 7.1.2 default validator chain is htm,
 * htu, iat, jkt, ath, then DPoPProofReplayValidator, failing fast on the first error. Its
 * InMemoryCache holds at most 100,000 entries and 1000 per client key, keeps each entry
 * until iat + 30 s, and rejects a proof when either limit is reached. Those limits are
 * the object under test.
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
			// 7.x installs DPoP only when asked; 6.5 installed it whenever the class was present.
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()).dPoP(Customizer.withDefaults()));
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
