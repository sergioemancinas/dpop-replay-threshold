package io.github.sergioemancinas.d2;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.server.resource.authentication.DPoPAuthenticationProvider;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the one structural assumption the Redis condition rests on.
 *
 * Spring Security 6.5.5 gives no supported way to replace the DPoP proof verifier:
 * DPoPAuthenticationConfigurer is package private and constructs DPoPAuthenticationProvider
 * inline (spring-projects/spring-security#18120). The shared cache is installed by
 * registering a provider that runs earlier in the ProviderManager, and ProviderManager stops
 * at the first provider that returns a result. If that ordering ever inverts, the library
 * provider answers first, Redis is never consulted, and every cross-replica replay is
 * admitted while the suite still reports a healthy stack. This test fails instead.
 */
@SpringBootTest(properties = {
		"dpop.jti.cache=redis",
		"node.id=test-node",
		// No network is touched. The decoder is built from the JWK set URI lazily and the
		// issuer URI is only used to construct a claim validator.
		"spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8180/realms/dpop-demo",
		"spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8180/realms/dpop-demo/protocol/openid-connect/certs" })
class SharedJtiWiringTests {

	@Autowired
	private FilterChainProxy filterChainProxy;

	@Autowired
	private SharedJtiDPoPAuthenticationProvider sharedJti;

	@Test
	void sharedJtiProviderPrecedesTheLibraryProvider() {
		List<AuthenticationProvider> providers = dPoPProviderChain();

		int shared = providers.indexOf(this.sharedJti);
		int library = indexOfType(providers, DPoPAuthenticationProvider.class);

		assertThat(shared).as("shared-cache provider is registered").isNotNegative();
		assertThat(library).as("library provider is still registered").isNotNegative();
		assertThat(shared).as("shared-cache provider must be consulted first").isLessThan(library);
	}

	private List<AuthenticationProvider> dPoPProviderChain() {
		SecurityFilterChain chain = this.filterChainProxy.getFilterChains().get(0);
		AuthenticationFilter filter = chain.getFilters()
			.stream()
			.filter(AuthenticationFilter.class::isInstance)
			.map(AuthenticationFilter.class::cast)
			.findFirst()
			.orElseThrow(() -> new AssertionError("no AuthenticationFilter in the chain"));
		// AuthenticationFilter keeps the manager behind a resolver and exposes neither, so
		// the resolver is read reflectively and then asked, through its own API, for the
		// manager this request would use.
		@SuppressWarnings("unchecked")
		AuthenticationManagerResolver<HttpServletRequest> resolver =
				(AuthenticationManagerResolver<HttpServletRequest>) ReflectionTestUtils
					.getField(filter, "authenticationManagerResolver");
		AuthenticationManager manager = unwrap(resolver.resolve(new MockHttpServletRequest()));
		assertThat(manager).isInstanceOf(ProviderManager.class);
		return ((ProviderManager) manager).getProviders();
	}

	/** Actuator on the classpath means the manager arrives wrapped for observation. */
	private static AuthenticationManager unwrap(AuthenticationManager manager) {
		while (!(manager instanceof ProviderManager)) {
			Object delegate = ReflectionTestUtils.getField(manager, "delegate");
			if (!(delegate instanceof AuthenticationManager next)) {
				return manager;
			}
			manager = next;
		}
		return manager;
	}

	private static int indexOfType(List<AuthenticationProvider> providers, Class<?> type) {
		for (int i = 0; i < providers.size(); i++) {
			if (type.isInstance(providers.get(i))) {
				return i;
			}
		}
		return -1;
	}
}
