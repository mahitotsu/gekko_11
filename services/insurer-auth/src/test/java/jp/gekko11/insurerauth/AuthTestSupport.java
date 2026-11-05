package jp.gekko11.insurerauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** 認可サーバーのテストの共通の手順。証明書は、TLS の層が確かめた後の形（要求の属性）で渡す。 */
@SpringBootTest(properties = { "gekko.issuer=http://localhost", "gekko.namespace=secure",
		"gekko.login-issuer=" + AuthTestSupport.LOGIN_ISSUER })
@AutoConfigureMockMvc
@Import(AuthTestSupport.LoginServer.class)
abstract class AuthTestSupport {

	static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

	static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

	static final String LOGIN_ISSUER = "http://login.test/realms/insurer";

	/** ログインサーバーの発行の鍵の代わり。 */
	static final RSAKey LOGIN_KEY = rsaKey();

	static final String TERMS = "[{\"type\":\"insurance_application\",\"kinds\":[\"annuity\"],\"maxBenefit\":1200000}]";

	static X509Certificate svid(String sa) {
		return TestCertificates.svid("spiffe://gekko11.internal/ns/secure/sa/" + sa);
	}

	@Autowired
	MockMvc mvc;

	final ObjectMapper json = new ObjectMapper();

	/** ログインサーバーの代わりに、公開鍵を渡す。 */
	@TestConfiguration
	static class LoginServer {

		@Bean
		@Primary
		LoginKeys testLoginKeys() {
			return new LoginKeys(new ImmutableJWKSet<>(new JWKSet(LOGIN_KEY.toPublicJWK())));
		}

	}

	String customerToken(ECKey dpopKey) throws Exception {
		return customerToken(dpopKey, "alice");
	}

	/** ログインサーバーが出す A（realm の設定と同じ形）。 */
	String customerToken(ECKey dpopKey, String user) throws Exception {
		return loginToken(LOGIN_KEY, "at+jwt", aClaims(dpopKey, user).build());
	}

	JWTClaimsSet.Builder aClaims(ECKey dpopKey, String user) throws Exception {
		JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(LOGIN_ISSUER)
			.subject(user)
			.audience("sales-agent")
			.jwtID("onrtac:" + UUID.randomUUID())
			.issueTime(new Date())
			.expirationTime(new Date(System.currentTimeMillis() + 300_000))
			.claim("azp", "customer-app")
			.claim("scope", "openid apply")
			.claim("cnf", Map.of("jkt", dpopKey.computeThumbprint().toString()))
			.claim("may_act", Map.of("iss", "http://localhost", "sub", "sales-agent"))
			.claim("authorization_details", this.json.readValue(TERMS, List.class));
		if (!"mallory".equals(user)) {
			claims.claim("verified_claims", Map.of("verification", Map.of("trust_framework", "jp_aml")));
		}
		return claims;
	}

	static String loginToken(RSAKey key, String type, JWTClaimsSet claims) throws Exception {
		SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID())
			.type(new JOSEObjectType(type))
			.build(), claims);
		token.sign(new RSASSASigner(key));
		return token.serialize();
	}

	static RSAKey rsaKey() {
		try {
			return new RSAKeyGenerator(2048).keyID("login").generate();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	String actorToken(X509Certificate cert, String clientId) throws Exception {
		MvcResult result = clientCredentials(cert, clientId);
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return (String) this.json.readValue(result.getResponse().getContentAsString(), Map.class).get("access_token");
	}

	MvcResult clientCredentials(X509Certificate cert, String clientId) throws Exception {
		return this.mvc
			.perform(post("/oauth2/token").param("grant_type", "client_credentials")
				.param("client_id", clientId)
				.with(x509(cert)))
			.andReturn();
	}

	String exchange(X509Certificate cert, String clientId, String subject, String actor, String audience)
			throws Exception {
		MvcResult result = this.mvc.perform(exchangeRequest(cert, clientId, subject, actor, audience)).andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return (String) this.json.readValue(result.getResponse().getContentAsString(), Map.class).get("access_token");
	}

	String refusal(X509Certificate cert, String clientId, String subject, String actor, String audience)
			throws Exception {
		MvcResult result = this.mvc.perform(exchangeRequest(cert, clientId, subject, actor, audience)).andReturn();
		assertThat(result.getResponse().getStatus()).isEqualTo(400);
		return result.getResponse().getContentAsString();
	}

	static MockHttpServletRequestBuilder exchangeRequest(X509Certificate cert, String clientId,
			String subject, String actor, String audience) {
		MockHttpServletRequestBuilder request = post("/oauth2/token").param("grant_type", TOKEN_EXCHANGE)
			.param("client_id", clientId)
			.param("subject_token", subject)
			.param("subject_token_type", ACCESS_TOKEN_TYPE)
			.param("audience", audience)
			.param("scope", "apply")
			.with(x509(cert));
		if (actor != null) {
			request.param("actor_token", actor).param("actor_token_type", ACCESS_TOKEN_TYPE);
		}
		return request;
	}

	/** passkey の受け口へ示す proof。 */
	static String dpopProof(ECKey key, String method, String uri, String token) throws Exception {
		SignedJWT proof = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
					.jwk(key.toPublicJWK())
					.build(),
				new JWTClaimsSet.Builder().claim("htm", method)
					.claim("htu", uri)
					.claim("ath", Base64.getUrlEncoder()
						.withoutPadding()
						.encodeToString(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII))))
					.issueTime(new Date())
					.jwtID(UUID.randomUUID().toString())
					.build());
		proof.sign(new ECDSASigner(key));
		return proof.serialize();
	}

	static Map<String, Object> claims(String jwt) throws Exception {
		SignedJWT parsed = SignedJWT.parse(jwt);
		assertThat(parsed.getHeader().getType().getType()).isEqualTo("at+jwt");
		return parsed.getJWTClaimsSet().toJSONObject();
	}

	static Map<String, Object> cnf(Map<String, Object> claims) {
		return map(claims.get("cnf"));
	}

	/** 宛先が 1 つだけなら、JWT の aud は文字列になる。 */
	static Object audience(Map<String, Object> claims) {
		Object aud = claims.get("aud");
		return (aud instanceof java.util.List<?> list && list.size() == 1) ? list.get(0) : aud;
	}

	@SuppressWarnings("unchecked")
	static Map<String, Object> map(Object value) {
		return (Map<String, Object>) value;
	}

	static String thumbprint(X509Certificate cert) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
