package io.github.sergioemancinas.rs.d4;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.DisableEncodeUrlFilter;

/**
 * Condition D4 wiring.
 *
 * <p>The framework's own {@code DPoPAuthenticationProvider} is displaced rather than
 * configured. {@code OAuth2ResourceServerConfigurer.configure} unconditionally applies
 * {@code DPoPAuthenticationConfigurer} whenever {@code DPoPProofJwtDecoderFactory} is on
 * the classpath, and that configurer registers its own provider with
 * {@code http.authenticationProvider(...)}, which appends to the
 * {@code AuthenticationManagerBuilder}. Registering a competing provider the same way is
 * not sufficient: {@code ProviderManager} continues to the next provider after an
 * {@code AuthenticationException}, so a nonce rejection would fall through to the
 * library provider, which does not check nonces.
 *
 * <p>Setting an explicit {@code AuthenticationManager} avoids that. {@code
 * HttpSecurity.beforeConfigure} short-circuits to the supplied instance and never builds
 * the {@code AuthenticationManagerBuilder}, so the provider the framework appends later is
 * inert, while the filters it creates still resolve the shared
 * {@code AuthenticationManager} and therefore use ours.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "d4.nonce.enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(NonceProperties.class)
class NonceSecurityConfig {

	@Bean
	DPoPNonceStore dPoPNonceStore(NonceProperties properties) {
		return new DPoPNonceStore(properties.getTtl(), properties.getMaxOutstanding());
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http, JwtDecoder jwtDecoder, DPoPNonceStore nonceStore)
			throws Exception {
		AuthenticationManager accessTokenAuthenticationManager = new ProviderManager(
				new JwtAuthenticationProvider(jwtDecoder));
		AuthenticationManager authenticationManager = new ProviderManager(
				new NonceAwareDPoPAuthenticationProvider(accessTokenAuthenticationManager, nonceStore),
				new JwtAuthenticationProvider(jwtDecoder));

		http.csrf(AbstractHttpConfigurer::disable)
			.authenticationManager(authenticationManager)
			.addFilterBefore(new DPoPNonceIssuingFilter(nonceStore), DisableEncodeUrlFilter.class)
			.authorizeHttpRequests((requests) -> requests.requestMatchers("/actuator/health")
				.permitAll()
				.anyRequest()
				.authenticated())
			.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		return http.build();
	}

}
