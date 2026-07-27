package io.github.sergioemancinas.rs.d4;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Supplies the access-token {@code JwtDecoder} so the tests need no authorization server.
 * Its presence also makes {@code OAuth2ResourceServerJwtConfiguration} back off, which is
 * why the tests do not need a reachable {@code jwk-set-uri}.
 */
@TestConfiguration(proxyBeanMethods = false)
class TestJwtDecoderConfig {

	@Bean
	JwtDecoder jwtDecoder() {
		return DPoPTestSupport.jwtDecoder();
	}

}
