package io.github.sergioemancinas.rs.d4;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Store of outstanding resource-server-provided DPoP nonces.
 *
 * <p>Nothing in Spring Security 6.5.5 corresponds to this class. RFC 9449 Section 9 lets a
 * resource server supply nonces the same way an authorization server does under Sections 8
 * and 8.2; the library ships no nonce issuance, no nonce claim validation and no
 * {@code use_dpop_nonce} error code. This is the state an implementer has to write.
 *
 * <p>Two properties are enforced here that RFC 9449 does <em>not</em> require:
 *
 * <ul>
 * <li><b>Single use.</b> {@link #consume} removes the entry, so a nonce is accepted exactly
 * once. RFC 9449 Section 11.1 states the opposite is acceptable ("it is acceptable for
 * clients to use the same nonce multiple times and for the server to accept the same nonce
 * multiple times"), because the RFC leaves replay defence to {@code jti} tracking and uses
 * the nonce only to bound the window over which that tracking must hold. Strict single use
 * is the stronger property required by the formal analysis, and it is what makes replay
 * rejection independent of the {@code jti} cache bound.</li>
 * <li><b>Key binding.</b> A nonce is bound to the JWK thumbprint of the key that requested
 * it, so a nonce issued to one client key cannot be presented by another.</li>
 * </ul>
 *
 * <p>State is bounded by {@code maxOutstanding}. Unlike the library's {@code jti} cache,
 * overflow here fails closed: evicting an outstanding nonce costs the affected client one
 * extra round trip (it receives {@code use_dpop_nonce} and retries), it does not admit a
 * replayed proof. The occupancy is also of a different order. The {@code jti} cache must
 * hold one entry per request accepted within the acceptance window, so it scales with
 * request rate. This store holds one entry per client key with a request in flight, so it
 * scales with client concurrency.
 */
public final class DPoPNonceStore {

	/**
	 * RFC 9449 Section 8.1 constrains the nonce to {@code 1*NQCHAR}. Base64url of 32 random
	 * bytes satisfies that and satisfies "Nonce values MUST be unpredictable".
	 */
	private static final int NONCE_BYTES = 32;

	private final SecureRandom random = new SecureRandom();

	private final ConcurrentHashMap<String, Entry> outstanding = new ConcurrentHashMap<>();

	private final Duration ttl;

	private final int maxOutstanding;

	private final Clock clock;

	public DPoPNonceStore(Duration ttl, int maxOutstanding) {
		this(ttl, maxOutstanding, Clock.systemUTC());
	}

	DPoPNonceStore(Duration ttl, int maxOutstanding, Clock clock) {
		if (ttl.isNegative() || ttl.isZero()) {
			throw new IllegalArgumentException("ttl must be positive");
		}
		if (maxOutstanding < 1) {
			throw new IllegalArgumentException("maxOutstanding must be >= 1");
		}
		this.ttl = ttl;
		this.maxOutstanding = maxOutstanding;
		this.clock = clock;
	}

	/**
	 * Issues a fresh nonce bound to {@code jkt}.
	 *
	 * <p>The caller supplies a thumbprint read from the {@code jwk} header of an
	 * as-yet-unverified proof. That is deliberate and safe: the binding decides who may
	 * later spend the nonce, and only the holder of the corresponding private key can
	 * produce a proof that survives signature verification. An attacker can mint nonces
	 * against a victim's public thumbprint but cannot spend them.
	 */
	public String issue(String jkt) {
		evictExpired();
		if (this.outstanding.size() >= this.maxOutstanding) {
			evictEarliestExpiring();
		}
		byte[] bytes = new byte[NONCE_BYTES];
		this.random.nextBytes(bytes);
		String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		this.outstanding.put(nonce, new Entry(jkt, this.clock.instant().plus(this.ttl)));
		return nonce;
	}

	/**
	 * Spends {@code nonce}. Returns {@code true} exactly once per issued nonce, and only
	 * for the key it was issued to.
	 */
	public boolean consume(String nonce, String jkt) {
		if (nonce == null || jkt == null) {
			return false;
		}
		Entry entry = this.outstanding.get(nonce);
		// Check the key binding before spending the nonce, so a request under another key
		// cannot burn the nonce of the client it was issued to.
		if (entry == null || !entry.jkt().equals(jkt)) {
			return false;
		}
		// Conditional remove: of two concurrent requests with this nonce, exactly one wins.
		if (!this.outstanding.remove(nonce, entry)) {
			return false;
		}
		return !this.clock.instant().isAfter(entry.expiresAt());
	}

	int outstandingCount() {
		return this.outstanding.size();
	}

	private void evictExpired() {
		Instant now = this.clock.instant();
		this.outstanding.entrySet().removeIf((entry) -> now.isAfter(entry.getValue().expiresAt()));
	}

	private void evictEarliestExpiring() {
		this.outstanding.entrySet()
			.stream()
			.min(Comparator.comparing((entry) -> entry.getValue().expiresAt()))
			.map(Map.Entry::getKey)
			.ifPresent(this.outstanding::remove);
	}

	private record Entry(String jkt, Instant expiresAt) {
	}

}
