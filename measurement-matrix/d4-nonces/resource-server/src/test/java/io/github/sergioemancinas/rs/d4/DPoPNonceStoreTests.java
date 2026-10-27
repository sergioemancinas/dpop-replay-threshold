package io.github.sergioemancinas.rs.d4;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class DPoPNonceStoreTests {

	private static final String JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

	@Test
	void aNonceIsAcceptedExactlyOnce() {
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofMinutes(5), 100);
		String nonce = store.issue(JKT);

		assertThat(store.consume(nonce, JKT)).isTrue();
		assertThat(store.consume(nonce, JKT)).as("single use").isFalse();
	}

	@Test
	void aNonceIsBoundToTheKeyItWasIssuedTo() {
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofMinutes(5), 100);
		String nonce = store.issue(JKT);

		assertThat(store.consume(nonce, "some-other-thumbprint")).isFalse();
		assertThat(store.consume(nonce, JKT)).as("a wrong-key attempt does not burn the nonce").isTrue();
	}

	@Test
	void anUnknownNonceIsRejected() {
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofMinutes(5), 100);

		assertThat(store.consume("not-a-nonce", JKT)).isFalse();
		assertThat(store.consume(null, JKT)).isFalse();
	}

	@Test
	void anExpiredNonceIsRejected() {
		MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofSeconds(30), 100, clock);
		String nonce = store.issue(JKT);

		clock.advance(Duration.ofSeconds(31));

		assertThat(store.consume(nonce, JKT)).isFalse();
	}

	@Test
	void issuedValuesAreDistinctAndOfFullEntropy() {
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofMinutes(5), 10_000);
		Set<String> seen = new HashSet<>();
		for (int i = 0; i < 5_000; i++) {
			String nonce = store.issue(JKT);
			assertThat(nonce).hasSize(43); // base64url of 32 bytes, unpadded
			assertThat(seen.add(nonce)).isTrue();
		}
	}

	@Test
	void expiredEntriesAreReclaimedOnIssue() {
		MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofSeconds(30), 1_000, clock);
		for (int i = 0; i < 100; i++) {
			store.issue(JKT);
		}
		assertThat(store.outstandingCount()).isEqualTo(100);

		clock.advance(Duration.ofSeconds(31));
		store.issue(JKT);

		assertThat(store.outstandingCount()).as("the 100 expired entries are reclaimed").isEqualTo(1);
	}

	/**
	 * Overflow fails closed. The bound is never exceeded and the eviction costs a client one
	 * extra round trip, in contrast to {@code JtiCache}, whose eviction admits a replay.
	 */
	@Test
	void overflowEvictsRatherThanGrows() {
		DPoPNonceStore store = new DPoPNonceStore(Duration.ofMinutes(5), 8);
		String first = store.issue(JKT);
		for (int i = 0; i < 32; i++) {
			store.issue(JKT);
		}

		assertThat(store.outstandingCount()).isLessThanOrEqualTo(8);
		assertThat(store.consume(first, JKT)).as("the evicted nonce is rejected, not silently honoured").isFalse();
	}

	private static final class MutableClock extends Clock {

		private Instant now;

		private MutableClock(Instant now) {
			this.now = now;
		}

		private void advance(Duration duration) {
			this.now = this.now.plus(duration);
		}

		@Override
		public ZoneOffset getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(java.time.ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return this.now;
		}

	}

}
