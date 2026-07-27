package io.github.sergioemancinas.d2;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * One replica of the three-replica DPoP resource server used by condition D2.
 *
 * The replay cache is selected by {@code dpop.jti.cache}:
 *
 * <ul>
 * <li>{@code default} leaves Spring Security untouched. {@code DPoPProofJwtDecoderFactory}
 * installs htm, htu, {@code JtiClaimValidator}, {@code JwtIssuedAtValidator}, and that
 * {@code JtiClaimValidator} is backed by a {@code static LinkedHashMap} private to the
 * process. Across replicas there is no shared state at all, which is the multi-node case
 * reported as spring-projects/spring-security#18120.</li>
 * <li>{@code redis} adds a shared jti cache. See {@link SharedJtiCacheConfiguration}.</li>
 * </ul>
 */
@SpringBootApplication
public class ResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceServerApplication.class, args);
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http,
			ObjectProvider<SharedJtiDPoPAuthenticationProvider> sharedJti) throws Exception {
		// Registered here, before http.build(). OAuth2ResourceServerConfigurer installs its
		// own DPoPAuthenticationProvider during its configure phase, which runs later, and
		// ProviderManager tries providers in registration order. Ordering is the only lever
		// available: DPoPAuthenticationConfigurer is package private and constructs that
		// provider inline, so there is no supported way to replace it (#18120).
		sharedJti.ifAvailable(http::authenticationProvider);
		http
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/actuator/health").permitAll()
				.anyRequest().authenticated())
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

	/**
	 * Stamps the replica identity on every response.
	 *
	 * It has to be a filter rather than a controller concern: the interesting responses are
	 * 401s produced inside the security filter chain, which never reach a controller, and
	 * attributing a rejection to a replica is what the experiment measures.
	 */
	@Bean
	FilterRegistrationBean<Filter> nodeIdentityFilter(@Value("${node.id}") String nodeId,
			@Value("${dpop.jti.cache}") String jtiCache) {
		FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>(
				(request, response, chain) -> {
					HttpServletResponse http = (HttpServletResponse) response;
					http.setHeader("X-Node-Id", nodeId);
					// Echoed so a test cannot report a Redis result while the stack is
					// actually running the default cache.
					http.setHeader("X-Jti-Cache", jtiCache);
					chain.doFilter(request, response);
				});
		registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return registration;
	}

	@RestController
	static class ProtectedResource {

		private final String nodeId;

		private final String jtiCache;

		ProtectedResource(@Value("${node.id}") String nodeId,
				@Value("${dpop.jti.cache}") String jtiCache) {
			this.nodeId = nodeId;
			this.jtiCache = jtiCache;
		}

		@GetMapping("/api/resource")
		Map<String, String> resource() {
			return Map.of("status", "ok", "node", this.nodeId, "jtiCache", this.jtiCache);
		}
	}
}
