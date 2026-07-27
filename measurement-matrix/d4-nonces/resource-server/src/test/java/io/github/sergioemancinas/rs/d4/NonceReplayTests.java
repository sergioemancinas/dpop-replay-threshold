package io.github.sergioemancinas.rs.d4;

import com.nimbusds.jose.jwk.ECKey;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Condition D4. Everything asserted here is produced by the custom code in this package;
 * none of it is a capability of Spring Security 6.5.5.
 */
@SpringBootTest(properties = "d4.nonce.enabled=true")
@AutoConfigureMockMvc
@Import(TestJwtDecoderConfig.class)
class NonceReplayTests {

	private static final int EVICTION_INSERTIONS = 1024;

	private static final Duration IAT_WINDOW_BUDGET = Duration.ofSeconds(45);

	@Autowired
	private MockMvc mockMvc;

	/**
	 * The headline assertion. Same procedure as {@link BaselineReplayControlTests}, which
	 * ends in HTTP 200: the probe's {@code jti} is evicted, so the library's replay defence
	 * is spent. The replay is still rejected, because the nonce it carries was consumed by
	 * its first use.
	 *
	 * <p>The rejection cannot be attributed to the {@code jti} cache, and the test proves
	 * that rather than assuming it. {@code DelegatingOAuth2TokenValidator} accumulates the
	 * errors of every validator instead of short-circuiting, so seeing
	 * {@code use_dpop_nonce} on the response would not by itself show that the {@code jti}
	 * check passed. A witness {@code jti} inserted immediately after the probe, and
	 * therefore evicted strictly later than the probe under the insertion-ordered
	 * evict-eldest policy, is re-presented after the eviction loop. Its acceptance
	 * establishes that the probe's {@code jti} is no longer cached.
	 */
	@Test
	void replayIsRejectedAfterTheProbeJtiHasBeenEvicted() throws Exception {
		ECKey key = DPoPTestSupport.generate("client");
		String accessToken = DPoPTestSupport.accessToken(key);

		String nonce = challengeForNonce(key, accessToken);

		String probeJti = UUID.randomUUID().toString();
		String probe = DPoPTestSupport.proof(key, accessToken)
			.jti(probeJti)
			.issuedAt(Instant.now())
			.nonce(nonce)
			.serialise();

		Instant started = Instant.now();
		MvcResult probeResult = perform(accessToken, probe);
		assertThat(probeResult.getResponse().getStatus()).as("probe accepted on first use").isEqualTo(200);
		nonce = nonceHeader(probeResult);

		String witnessJti = UUID.randomUUID().toString();
		MvcResult witnessResult = perform(accessToken,
				DPoPTestSupport.proof(key, accessToken).jti(witnessJti).nonce(nonce).serialise());
		assertThat(witnessResult.getResponse().getStatus()).isEqualTo(200);
		nonce = nonceHeader(witnessResult);

		for (int i = 0; i < EVICTION_INSERTIONS; i++) {
			MvcResult fillerResult = perform(accessToken,
					DPoPTestSupport.proof(key, accessToken).nonce(nonce).serialise());
			assertThat(fillerResult.getResponse().getStatus()).as("filler request %d", i).isEqualTo(200);
			nonce = nonceHeader(fillerResult);
		}

		MvcResult witnessRecheck = perform(accessToken,
				DPoPTestSupport.proof(key, accessToken).jti(witnessJti).nonce(nonce).serialise());
		assertThat(witnessRecheck.getResponse().getStatus())
			.as("witness jti was evicted, so the probe jti, inserted earlier, was evicted too")
			.isEqualTo(200);

		MvcResult replay = perform(accessToken, probe);
		Duration elapsed = Duration.between(started, Instant.now());

		assertThat(elapsed).as("replay must land inside the iat acceptance window to be a valid test")
			.isLessThan(IAT_WINDOW_BUDGET);
		assertThat(replay.getResponse().getStatus()).isEqualTo(401);
		assertThat(replay.getResponse().getHeader("WWW-Authenticate"))
			.as("RFC 9449 Section 9 error signalling")
			.contains("error=\"use_dpop_nonce\"");
		assertThat(nonceHeader(replay)).as("rejection carries a fresh nonce so the client can recover").isNotBlank();
	}

	/**
	 * Single use isolated from the {@code jti} cache: a second proof with a fresh
	 * {@code jti} but a spent nonce is rejected. RFC 9449 Section 11.1 permits nonce reuse;
	 * this store deliberately does not.
	 */
	@Test
	void aSpentNonceIsNotAcceptedAgainEvenWithAFreshJti() throws Exception {
		ECKey key = DPoPTestSupport.generate("client");
		String accessToken = DPoPTestSupport.accessToken(key);
		String nonce = challengeForNonce(key, accessToken);

		assertThat(perform(accessToken, DPoPTestSupport.proof(key, accessToken).nonce(nonce).serialise()).getResponse()
			.getStatus()).isEqualTo(200);

		MvcResult reuse = perform(accessToken, DPoPTestSupport.proof(key, accessToken).nonce(nonce).serialise());
		assertThat(reuse.getResponse().getStatus()).isEqualTo(401);
		assertThat(reuse.getResponse().getHeader("WWW-Authenticate")).contains("error=\"use_dpop_nonce\"");
	}

	/** RFC 9449 Section 9, Figure 24. */
	@Test
	void proofWithoutNonceIsChallenged() throws Exception {
		ECKey key = DPoPTestSupport.generate("client");
		String accessToken = DPoPTestSupport.accessToken(key);

		MvcResult result = perform(accessToken, DPoPTestSupport.proof(key, accessToken).serialise());

		assertThat(result.getResponse().getStatus()).isEqualTo(401);
		assertThat(result.getResponse().getHeader("WWW-Authenticate")).startsWith("DPoP ")
			.contains("error=\"use_dpop_nonce\"");
		assertThat(nonceHeader(result)).isNotBlank();
		assertThat(result.getResponse().getHeaders(DPoPNonceIssuingFilter.DPOP_NONCE_HEADER))
			.as("RFC 9449 Section 8 permits at most one DPoP-Nonce header")
			.hasSize(1);
		assertThat(result.getResponse().getHeader("Cache-Control")).contains("no-store");
	}

	/** A nonce issued to one key cannot be spent by another. */
	@Test
	void nonceIssuedToAnotherKeyIsRejected() throws Exception {
		ECKey victim = DPoPTestSupport.generate("victim");
		String victimToken = DPoPTestSupport.accessToken(victim);
		String victimNonce = challengeForNonce(victim, victimToken);

		ECKey attacker = DPoPTestSupport.generate("attacker");
		String attackerToken = DPoPTestSupport.accessToken(attacker);

		MvcResult result = perform(attackerToken,
				DPoPTestSupport.proof(attacker, attackerToken).nonce(victimNonce).serialise());

		assertThat(result.getResponse().getStatus()).isEqualTo(401);
		assertThat(result.getResponse().getHeader("WWW-Authenticate")).contains("error=\"use_dpop_nonce\"");
	}

	/**
	 * The restated {@code ath} check still runs. Replacing the validator factory discards
	 * the library's private one, so this guards against silently dropping it.
	 */
	@Test
	void athMismatchIsStillRejected() throws Exception {
		ECKey key = DPoPTestSupport.generate("client");
		String accessToken = DPoPTestSupport.accessToken(key);
		String otherToken = DPoPTestSupport.accessToken(key);
		String nonce = challengeForNonce(key, accessToken);

		MvcResult result = perform(accessToken, DPoPTestSupport.proof(key, otherToken).nonce(nonce).serialise());

		assertThat(result.getResponse().getStatus()).isEqualTo(401);
		assertThat(result.getResponse().getHeader("WWW-Authenticate")).contains("error=\"invalid_dpop_proof\"");
	}

	/** The restated {@code cnf.jkt} check still runs. */
	@Test
	void jktMismatchIsStillRejected() throws Exception {
		ECKey bound = DPoPTestSupport.generate("bound");
		ECKey other = DPoPTestSupport.generate("other");
		String accessToken = DPoPTestSupport.accessToken(bound);
		String nonce = challengeForNonce(other, accessToken);

		MvcResult result = perform(accessToken, DPoPTestSupport.proof(other, accessToken).nonce(nonce).serialise());

		assertThat(result.getResponse().getStatus()).isEqualTo(401);
		assertThat(result.getResponse().getHeader("WWW-Authenticate")).contains("error=\"invalid_dpop_proof\"");
	}

	private String challengeForNonce(ECKey key, String accessToken) throws Exception {
		MvcResult challenge = perform(accessToken, DPoPTestSupport.proof(key, accessToken).serialise());
		assertThat(challenge.getResponse().getStatus()).isEqualTo(401);
		return nonceHeader(challenge);
	}

	private static String nonceHeader(MvcResult result) {
		return result.getResponse().getHeader(DPoPNonceIssuingFilter.DPOP_NONCE_HEADER);
	}

	private MvcResult perform(String accessToken, String proof) throws Exception {
		return this.mockMvc
			.perform(get(DPoPTestSupport.RESOURCE_PATH).header("Authorization", "DPoP " + accessToken)
				.header("DPoP", proof))
			.andReturn();
	}

}
