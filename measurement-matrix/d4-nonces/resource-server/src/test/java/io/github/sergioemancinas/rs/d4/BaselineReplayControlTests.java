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
 * Control for {@link NonceReplayTests}: Spring Security defaults, no nonce.
 *
 * <p>Establishes in-process what the D1 sweep establishes over the wire, that the bounded
 * {@code jti} cache admits a replayed proof once the probe entry has been evicted. Without
 * this the D4 rejection would be unattributable, because a rejection could simply mean the
 * cache still held the {@code jti}.
 *
 * <p>Eviction is driven by count rather than by rate. {@code JtiCache.removeEldestEntry}
 * returns true when {@code size() > 1000}, so the first entry is displaced by the
 * 1000th subsequent insertion. Driving that many insertions directly is equivalent to
 * sustaining {@code R > R*} for the acceptance window and is deterministic.
 */
@SpringBootTest(properties = "d4.nonce.enabled=false")
@AutoConfigureMockMvc
@Import(TestJwtDecoderConfig.class)
class BaselineReplayControlTests {

	/**
	 * {@code MAX_SIZE} is 1000 in {@code DPoPProofJwtDecoderFactory.JtiCache}, read from the
	 * 6.5.5 tag. 1024 insertions displaces the probe with margin.
	 */
	private static final int EVICTION_INSERTIONS = 1024;

	/**
	 * {@code JwtIssuedAtValidator} defaults to a 60 s clock skew, so the replayed proof must
	 * still be inside its {@code iat} window when it is presented.
	 */
	private static final Duration IAT_WINDOW_BUDGET = Duration.ofSeconds(45);

	@Autowired
	private MockMvc mockMvc;

	@Test
	void replayIsAdmittedOnceTheProbeJtiHasBeenEvicted() throws Exception {
		ECKey key = DPoPTestSupport.generate("client");
		String accessToken = DPoPTestSupport.accessToken(key);

		String probeJti = UUID.randomUUID().toString();
		Instant probeIssuedAt = Instant.now();
		String probe = DPoPTestSupport.proof(key, accessToken).jti(probeJti).issuedAt(probeIssuedAt).serialise();

		Instant started = Instant.now();
		assertThat(perform(accessToken, probe).getResponse().getStatus()).as("probe accepted on first use")
			.isEqualTo(200);

		for (int i = 0; i < EVICTION_INSERTIONS; i++) {
			String filler = DPoPTestSupport.proof(key, accessToken).serialise();
			assertThat(perform(accessToken, filler).getResponse().getStatus()).as("filler request %d", i)
				.isEqualTo(200);
		}

		int replayStatus = perform(accessToken, probe).getResponse().getStatus();
		Duration elapsed = Duration.between(started, Instant.now());

		assertThat(elapsed).as("replay must land inside the iat acceptance window to be a valid test")
			.isLessThan(IAT_WINDOW_BUDGET);
		assertThat(replayStatus)
			.as("library defaults admit the replay because the probe jti was evicted from the bounded cache")
			.isEqualTo(200);
	}

	private MvcResult perform(String accessToken, String proof) throws Exception {
		return this.mockMvc
			.perform(get(DPoPTestSupport.RESOURCE_PATH).header("Authorization", "DPoP " + accessToken)
				.header("DPoP", proof))
			.andReturn();
	}

}
