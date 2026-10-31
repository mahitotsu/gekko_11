package jp.gekko11.insurerbackend;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

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

import org.springframework.stereotype.Component;

/**
 * 顧客に示す案の一式に、保険会社の提示の鍵で署名する（P-1、E7）。提示の鍵は、トークンの発行の鍵と分ける（4-5）。
 * typ を offer+jwt にして、トークン（at+jwt）と取り違えられないようにする。
 */
@Component
class OfferSigner {

	static final String TYP = "offer+jwt";

	static final String ISSUER = "insurer-backend";

	private final ECKey key;

	OfferSigner() throws Exception {
		this.key = new ECKeyGenerator(Curve.P_256).keyID("offer-key-1").generate();
	}

	/** 提示集合の識別子（仮称）。案の全体の正規化のハッシュ。 */
	static String offerSetId(String customer, Object plans) {
		return Canonical.challengeOf(Map.of("customer", customer, "plans", plans));
	}

	String sign(String customer, List<Map<String, Object>> plans, String nonce, long expiresAt) throws Exception {
		JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER)
			.issueTime(new Date())
			.expirationTime(Date.from(Instant.ofEpochSecond(expiresAt)))
			.claim("customer", customer)
			.claim("plans", plans)
			.claim("offerSetId", offerSetId(customer, plans))
			.claim("nonce", nonce)
			.build();
		SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(TYP)).keyID(this.key.getKeyID()).build(),
				claims);
		jwt.sign(new ECDSASigner(this.key));
		return jwt.serialize();
	}

	/** alg、typ、iss、期限を固定して確かめ、案の一式から識別子を作り直して照らす。 */
	Map<String, Object> verify(String jws) throws Exception {
		SignedJWT jwt = SignedJWT.parse(jws);
		if (!JWSAlgorithm.ES256.equals(jwt.getHeader().getAlgorithm())
				|| !new JOSEObjectType(TYP).equals(jwt.getHeader().getType())) {
			throw new IllegalArgumentException("提示の形式が違う");
		}
		if (!jwt.verify(new ECDSAVerifier(this.key.toECPublicKey()))) {
			throw new IllegalArgumentException("提示の署名が違う");
		}
		JWTClaimsSet claims = jwt.getJWTClaimsSet();
		if (!ISSUER.equals(claims.getIssuer()) || claims.getExpirationTime().before(new Date())) {
			throw new IllegalArgumentException("提示の発行元か期限が違う");
		}
		Map<String, Object> payload = claims.toJSONObject();
		if (!offerSetId((String) payload.get("customer"), payload.get("plans")).equals(payload.get("offerSetId"))) {
			throw new IllegalArgumentException("提示集合の識別子が、案の内容と一致しない");
		}
		return payload;
	}

	Map<String, Object> jwks() {
		return Map.of("keys", List.of(this.key.toPublicJWK().toJSONObject()));
	}

}
