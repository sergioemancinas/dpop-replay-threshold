package io.github.sergioemancinas.rs.d4;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Condition D4: DPoP with resource-server-provided nonces, RFC 9449 Sections 8, 8.2 and 9.
 *
 * <p>Two security configurations are selectable so that the nonce condition can be compared
 * against the library default on the same code base:
 *
 * <ul>
 * <li>{@code d4.nonce.enabled=true} (default): {@link NonceSecurityConfig}, library
 * defaults plus the custom nonce machinery in this package.</li>
 * <li>{@code d4.nonce.enabled=false}: {@link BaselineSecurityConfig}, Spring Security
 * defaults only. This is the D1 control and it is expected to admit replay once the
 * {@code jti} cache has evicted the probe.</li>
 * </ul>
 */
@SpringBootApplication
public class D4ResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(D4ResourceServerApplication.class, args);
	}

	@RestController
	static class ProtectedResource {

		@GetMapping("/api/resource")
		Map<String, String> resource() {
			return Map.of("status", "ok");
		}

	}

}
