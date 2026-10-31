package jp.gekko11.insurerauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

/** 認可サーバーのテストの共通の手順。証明書は、TLS の層が確かめた後の形（要求の属性）で渡す。 */
@SpringBootTest(properties = { "gekko.issuer=http://localhost", "gekko.namespace=secure" })
@AutoConfigureMockMvc
abstract class AuthTestSupport {

	static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

	static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

	static final String REDIRECT = "http://127.0.0.1:4000/callback";

	static final String TERMS = "[{\"type\":\"insurance_application\",\"kinds\":[\"annuity\"],\"maxBenefit\":1200000}]";

	static X509Certificate svid(String sa) {
		return TestCertificates.svid("spiffe://gekko11.internal/ns/secure/sa/" + sa);
	}

	@Autowired
	MockMvc mvc;

	final ObjectMapper json = new ObjectMapper();

	String customerToken(ECKey dpopKey) throws Exception {
		return customerToken(dpopKey, "alice");
	}

	String customerToken(ECKey dpopKey, String user) throws Exception {
		String verifier = UUID.randomUUID() + "-" + UUID.randomUUID();
		MvcResult result = this.mvc
			.perform(post("/oauth2/token").param("grant_type", "authorization_code")
				.param("client_id", "customer-app")
				.param("code", authorizationCode(verifier, user))
				.param("redirect_uri", REDIRECT)
				.param("code_verifier", verifier)
				.header("DPoP", dpopProof(dpopKey)))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		Map<?, ?> body = this.json.readValue(result.getResponse().getContentAsString(), Map.class);
		assertThat(body.get("token_type")).isEqualTo("DPoP");
		return (String) body.get("access_token");
	}

	String authorizationCode(String verifier) throws Exception {
		return authorizationCode(verifier, "alice");
	}

	String authorizationCode(String verifier, String user) throws Exception {
		MvcResult result = this.mvc
			.perform(get(UriComponentsBuilder.fromPath("/oauth2/authorize")
				.queryParam("response_type", "code")
				.queryParam("client_id", "customer-app")
				.queryParam("scope", "openid apply")
				.queryParam("authorization_details", TERMS)
				.queryParam("redirect_uri", REDIRECT)
				.queryParam("state", "s")
				.queryParam("code_challenge", challenge(verifier))
				.queryParam("code_challenge_method", "S256")
				.build()
				.encode()
				.toUri()).with(user(user)))
			.andReturn();
		String location = result.getResponse().getRedirectedUrl();
		assertThat(location).startsWith(REDIRECT);
		return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
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

	static String dpopProof(ECKey key) throws Exception {
		SignedJWT proof = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
					.jwk(key.toPublicJWK())
					.build(),
				new JWTClaimsSet.Builder().claim("htm", "POST")
					.claim("htu", "http://localhost/oauth2/token")
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

	static String challenge(String verifier) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	static String thumbprint(X509Certificate cert) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
