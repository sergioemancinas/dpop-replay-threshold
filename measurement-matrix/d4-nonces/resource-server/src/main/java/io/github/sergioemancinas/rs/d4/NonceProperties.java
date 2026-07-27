package io.github.sergioemancinas.rs.d4;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Nonce store tuning. RFC 9449 leaves nonce lifetime and rotation policy to the server
 * ("The logic through which the server makes that determination is out of scope of this
 * document", Section 8).
 */
@ConfigurationProperties(prefix = "d4.nonce")
public class NonceProperties {

	/** Whether the nonce condition is active. Read by {@code @ConditionalOnProperty}. */
	private boolean enabled = true;

	/**
	 * How long an issued but unspent nonce remains acceptable. Short by design: with strict
	 * single use the TTL bounds only the memory held for clients that abandon a request.
	 */
	private Duration ttl = Duration.ofSeconds(300);

	/**
	 * Cap on simultaneously outstanding nonces. Sized to client concurrency, not to request
	 * rate. Overflow evicts the earliest-expiring entry, which costs that client one extra
	 * round trip; it does not admit a replayed proof.
	 */
	private int maxOutstanding = 100_000;

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public Duration getTtl() {
		return this.ttl;
	}

	public void setTtl(Duration ttl) {
		this.ttl = ttl;
	}

	public int getMaxOutstanding() {
		return this.maxOutstanding;
	}

	public void setMaxOutstanding(int maxOutstanding) {
		this.maxOutstanding = maxOutstanding;
	}

}
