package io.github.sergioemancinas.d2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.springframework.data.redis.connection.RedisStringCommands.SetOption;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.types.Expiration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Single-use enforcement for the DPoP proof {@code jti} against a cache shared by every
 * replica.
 *
 * The primitive is {@code SET key value NX EX ttl}: one round trip that both tests for and
 * claims the identifier, so two replicas racing the same proof cannot both win.
 *
 * This mirrors the semantics of Spring Security's own {@code JtiClaimValidator}, which is
 * private and process local, including hashing the identifier before it is used as a key.
 */
final class RedisJtiClaimValidator implements OAuth2TokenValidator<Jwt> {

	private final StringRedisTemplate redis;

	private final String keyPrefix;

	private final long ttlSeconds;

	private final String nodeId;

	RedisJtiClaimValidator(StringRedisTemplate redis, String keyPrefix, long ttlSeconds, String nodeId) {
		Assert.notNull(redis, "redis cannot be null");
		Assert.hasText(keyPrefix, "keyPrefix cannot be empty");
		Assert.isTrue(ttlSeconds > 0, "ttlSeconds must be > 0");
		this.redis = redis;
		this.keyPrefix = keyPrefix;
		this.ttlSeconds = ttlSeconds;
		this.nodeId = nodeId;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Assert.notNull(jwt, "DPoP proof jwt cannot be null");
		String jti = jwt.getId();
		if (!StringUtils.hasText(jti)) {
			return failure("jti claim is required.");
		}

		String key;
		try {
			key = this.keyPrefix + computeSHA256(jti);
		}
		catch (Exception ex) {
			return failure("jti claim is invalid.");
		}

		Boolean claimed;
		try {
			claimed = setIfAbsent(key);
		}
		catch (RuntimeException ex) {
			// Fail closed. Single use is the entire replay defence in RFC 9449 Sec. 11.1;
			// with the shared cache unreachable it cannot be enforced, and accepting the
			// proof would silently reinstate the multi-node hole this condition exists to
			// close.
			return failure("jti claim could not be validated.");
		}
		if (!Boolean.TRUE.equals(claimed)) {
			// Key already present, so some replica has already spent this proof. A null
			// reply is not a success either and lands here by design.
			return failure("jti claim is invalid.");
		}
		return OAuth2TokenValidatorResult.success();
	}

	private Boolean setIfAbsent(String key) {
		// Issued through the low-level string commands rather than opsForValue so the wire
		// command is unambiguously SET key value EX ttl NX. The value is diagnostic only:
		// NX makes the existence of the key the decision.
		byte[] rawKey = key.getBytes(StandardCharsets.UTF_8);
		byte[] rawValue = this.nodeId.getBytes(StandardCharsets.UTF_8);
		return this.redis.execute((RedisCallback<Boolean>) connection -> connection.stringCommands()
			.set(rawKey, rawValue, Expiration.seconds(this.ttlSeconds), SetOption.ifAbsent()));
	}

	private static OAuth2TokenValidatorResult failure(String reason) {
		return OAuth2TokenValidatorResult
			.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, reason, null));
	}

	private static String computeSHA256(String value) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}
}
