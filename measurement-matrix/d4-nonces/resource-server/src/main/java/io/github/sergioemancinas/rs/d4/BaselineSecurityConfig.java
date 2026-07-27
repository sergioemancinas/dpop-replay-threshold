package io.github.sergioemancinas.rs.d4;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Library defaults, no custom code in the DPoP path. Identical in substance to the D1
 * resource server in {@code ../../single-host-validation/}.
 *
 * <p>Present as the control for the D4 test: it establishes that the probe proof really was
 * evicted from the bounded {@code jti} cache, so that the D4 rejection can be attributed to
 * the nonce and not to the cache still holding the {@code jti}.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "d4.nonce.enabled", havingValue = "false")
class BaselineSecurityConfig {

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
			.authorizeHttpRequests((requests) -> requests.requestMatchers("/actuator/health")
				.permitAll()
				.anyRequest()
				.authenticated())
			.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

}
