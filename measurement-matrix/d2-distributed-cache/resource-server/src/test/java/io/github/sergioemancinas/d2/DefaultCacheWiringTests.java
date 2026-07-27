package io.github.sergioemancinas.d2;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The other half of the switch. In default-cache mode nothing of this artifact's may be in
 * the authentication path, or condition D2's baseline is not Spring Security's baseline and
 * fact 1 measures something else.
 */
@SpringBootTest(properties = {
		"dpop.jti.cache=default",
		"node.id=test-node",
		"spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8180/realms/dpop-demo",
		"spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8180/realms/dpop-demo/protocol/openid-connect/certs" })
class DefaultCacheWiringTests {

	@Autowired
	private ApplicationContext context;

	@Test
	void noSharedCacheProviderIsRegistered() {
		assertThat(this.context.getBeanNamesForType(SharedJtiDPoPAuthenticationProvider.class)).isEmpty();
	}
}
