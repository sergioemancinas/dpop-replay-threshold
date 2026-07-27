package io.github.sergioemancinas.rs.d4;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Proof and access-token construction for the tests.
 *
 * <p>Mirrors {@code ../../../single-host-validation/load/dpop.py}: ES256 throughout, and a
 * proof is replayed by presenting the same {@code jti} with the same {@code iat}, not by
 * minting a fresh one.
 *
 * <p>No Keycloak here. The access token is minted by a local key and decoded by
 * {@link #jwtDecoder()}, because these tests exercise proof validation, not token issuance.
 */
final class DPoPTestSupport {

	static final String RESOURCE_PATH = "/api/resource";

	static final String RESOURCE_URI = "http://localhost" + RESOURCE_PATH;

	private static final ECKey AUTHORIZATION_SERVER_KEY = generate("as-signing-key");

	private DPoPTestSupport() {
	}

	static ECKey generate(String kid) {
		try {
			return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	/** RFC 7638 thumbprint, the value that appears as {@code cnf.jkt}. */
	static String thumbprint(ECKey key) {
		try {
			return key.toPublicJWK().computeThumbprint().toString();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	/** A DPoP-bound access token whose {@code cnf.jkt} is the thumbprint of {@code key}. */
	static String accessToken(ECKey key) {
		Instant now = Instant.now();
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("https://as.test/realms/dpop-demo")
			.subject("testuser")
			.issueTime(Date.from(now))
			.expirationTime(Date.from(now.plus(30, ChronoUnit.MINUTES)))
			.claim("cnf", Map.of("jkt", thumbprint(key)))
			.build();
		try {
			SignedJWT token = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(AUTHORIZATION_SERVER_KEY.getKeyID()).build(),
					claims);
			token.sign(new ECDSASigner(AUTHORIZATION_SERVER_KEY));
			return token.serialize();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	static JwtDecoder jwtDecoder() {
		return (token) -> {
			try {
				SignedJWT parsed = SignedJWT.parse(token);
				if (!parsed.verify(new ECDSAVerifier(AUTHORIZATION_SERVER_KEY.toPublicJWK()))) {
					throw new BadJwtException("Access token signature is invalid.");
				}
				Map<String, Object> claims = new HashMap<>(parsed.getJWTClaimsSet().getClaims());
				claims.replaceAll((name, value) -> (value instanceof Date date) ? date.toInstant() : value);
				return Jwt.withTokenValue(token)
					.headers((headers) -> headers.putAll(parsed.getHeader().toJSONObject()))
					.claims((target) -> {
						target.clear();
						target.putAll(claims);
					})
					.build();
			}
			catch (BadJwtException ex) {
				throw ex;
			}
			catch (Exception ex) {
				throw new BadJwtException("Access token is malformed.", ex);
			}
		};
	}

	static Proof proof(ECKey key, String accessToken) {
		return new Proof(key, accessToken);
	}

	/**
	 * A DPoP proof under construction. {@code jti} and {@code iat} are explicit so a proof
	 * can be replayed byte for byte.
	 */
	static final class Proof {

		private final ECKey key;

		private final String accessToken;

		private String method = "GET";

		private String targetUri = RESOURCE_URI;

		private String jti = UUID.randomUUID().toString();

		private Instant issuedAt = Instant.now();

		private String nonce;

		private Proof(ECKey key, String accessToken) {
			this.key = key;
			this.accessToken = accessToken;
		}

		Proof jti(String jti) {
			this.jti = jti;
			return this;
		}

		Proof issuedAt(Instant issuedAt) {
			this.issuedAt = issuedAt;
			return this;
		}

		Proof nonce(String nonce) {
			this.nonce = nonce;
			return this;
		}

		String serialise() {
			JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
				.jwk(this.key.toPublicJWK())
				.build();
			JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().claim("htm", this.method)
				.claim("htu", this.targetUri)
				.jwtID(this.jti)
				.issueTime(Date.from(this.issuedAt))
				.claim("ath", sha256Base64Url(this.accessToken));
			if (this.nonce != null) {
				claims.claim("nonce", this.nonce);
			}
			try {
				SignedJWT proof = new SignedJWT(header, claims.build());
				proof.sign(new ECDSASigner(this.key));
				return proof.serialize();
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
		}

	}

	static String sha256Base64Url(String value) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

}
