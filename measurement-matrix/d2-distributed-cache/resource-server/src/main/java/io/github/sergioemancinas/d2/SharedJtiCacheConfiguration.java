package io.github.sergioemancinas.d2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

/**
 * Installs the Redis-backed shared {@code jti} cache. Active only when
 * {@code dpop.jti.cache=redis}; otherwise the replica runs on Spring Security defaults and
 * this class contributes nothing.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "dpop.jti.cache", havingValue = "redis")
class SharedJtiCacheConfiguration {

	@Bean
	SharedJtiDPoPAuthenticationProvider sharedJtiDPoPAuthenticationProvider(JwtDecoder jwtDecoder,
			StringRedisTemplate redis, @Value("${dpop.jti.key-prefix}") String keyPrefix,
			@Value("${dpop.jti.redis-ttl-seconds}") long ttlSeconds, @Value("${node.id}") String nodeId) {

		// The same access-token path OAuth2ResourceServerConfigurer would have built: the
		// auto-configured JwtDecoder behind a JwtAuthenticationProvider.
		AuthenticationManager tokenAuthenticationManager = new ProviderManager(
				new JwtAuthenticationProvider(jwtDecoder));
		DPoPAuthenticationProvider defaults = new DPoPAuthenticationProvider(tokenAuthenticationManager);

		OAuth2TokenValidator<Jwt> sharedJti = new RedisJtiClaimValidator(redis, keyPrefix, ttlSeconds, nodeId);
		DPoPProofJwtDecoderFactory sharedJtiVerifier = new DPoPProofJwtDecoderFactory();
		// setJwtValidatorFactory is the only public seam on this factory, and it replaces
		// the chain outright. DEFAULT_JWT_VALIDATOR_FACTORY is intentionally NOT composed in
		// here: the default chain has already run inside `defaults` above, and its
		// process-local JtiClaimValidator would then see its own insertion and reject every
		// request on its second pass.
		sharedJtiVerifier.setJwtValidatorFactory((context) -> sharedJti);

		return new SharedJtiDPoPAuthenticationProvider(defaults, sharedJtiVerifier);
	}
}
