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

/**
 * 段 0 の Q1 と Q2 を、TLS の層を除いて確かめる。証明書は、TLS の層が確かめた後の形（要求の属性）で渡す。
 * A（DPoP）→ B（営業 AI エージェントの証明書）→ C（事務サービスの証明書）と結び直し、act を積む。
 */
@SpringBootTest(properties = { "gekko.issuer=http://localhost", "gekko.namespace=secure" })
@AutoConfigureMockMvc
class ExchangeFlowTest {

	private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

	private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String REDIRECT = "http://127.0.0.1:4000/callback";

	private static final X509Certificate SALES_AGENT = TestCertificates
		.svid("spiffe://gekko11.internal/ns/secure/sa/sales-agent");

	private static final X509Certificate SALES_AGENT_OTHER_KEY = TestCertificates
		.svid("spiffe://gekko11.internal/ns/secure/sa/sales-agent");

	private static final X509Certificate INSURER_MCP = TestCertificates
		.svid("spiffe://gekko11.internal/ns/secure/sa/insurer-mcp");

	private static final X509Certificate INTRUDER = TestCertificates
		.svid("spiffe://gekko11.internal/ns/secure/sa/intruder");

	private static final X509Certificate OTHER_NAMESPACE = TestCertificates
		.svid("spiffe://gekko11.internal/ns/vulnerable/sa/sales-agent");

	@Autowired
	MockMvc mvc;

	private final ObjectMapper json = new ObjectMapper();

	@Test
	void tokenAIsBoundToTheDpopKeyAndMayBeActedOnBySalesAgent() throws Exception {
		ECKey dpopKey = new ECKeyGenerator(Curve.P_256).generate();
		Map<String, Object> a = claims(customerToken(dpopKey));

		assertThat(a.get("sub")).isEqualTo("alice");
		assertThat(audience(a)).isEqualTo("sales-agent");
		assertThat(cnf(a)).containsEntry("jkt", dpopKey.computeThumbprint().toString()).doesNotContainKey("x5t#S256");
		assertThat(map(a.get("may_act"))).containsEntry("sub", "sales-agent").containsEntry("iss", "http://localhost");
	}

	@Test
	void customerTokenWithoutDpopIsRefused() throws Exception {
		MvcResult result = this.mvc.perform(post("/oauth2/token").param("grant_type", "authorization_code")
			.param("client_id", "customer-app")
			.param("code", authorizationCode("v".repeat(43)))
			.param("redirect_uri", REDIRECT)
			.param("code_verifier", "v".repeat(43))).andReturn();
		assertThat(result.getResponse().getStatus()).isEqualTo(400);
	}

	@Test
	void exchangesRebindToTheRequesterCertificateAndNestAct() throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());

		String b = exchange(SALES_AGENT, "sales-agent", a, actorToken(SALES_AGENT, "sales-agent"), "insurer-mcp");
		Map<String, Object> bc = claims(b);
		assertThat(bc.get("sub")).isEqualTo("alice");
		assertThat(audience(bc)).isEqualTo("insurer-mcp");
		assertThat(cnf(bc)).containsEntry("x5t#S256", thumbprint(SALES_AGENT)).doesNotContainKey("jkt");
		assertThat(map(bc.get("act"))).containsEntry("sub", "sales-agent").doesNotContainKey("act");
		assertThat(map(bc.get("may_act"))).containsEntry("sub", "insurer-mcp");

		String c = exchange(INSURER_MCP, "insurer-mcp", b, actorToken(INSURER_MCP, "insurer-mcp"), "insurer-backend");
		Map<String, Object> cc = claims(c);
		assertThat(cc.get("sub")).isEqualTo("alice");
		assertThat(audience(cc)).isEqualTo("insurer-backend");
		assertThat(cnf(cc)).containsEntry("x5t#S256", thumbprint(INSURER_MCP));
		Map<String, Object> act = map(cc.get("act"));
		assertThat(act).containsEntry("sub", "insurer-mcp");
		assertThat(map(act.get("act"))).containsEntry("sub", "sales-agent");
		assertThat(cc).doesNotContainKey("may_act");
	}

	@Test
	void clientAuthenticationLooksAtTheSpiffeId() throws Exception {
		assertThat(clientCredentials(INTRUDER, "sales-agent").getResponse().getStatus()).isEqualTo(401);
		assertThat(clientCredentials(OTHER_NAMESPACE, "sales-agent").getResponse().getStatus()).isEqualTo(401);
		assertThat(this.mvc.perform(post("/oauth2/token").param("grant_type", "client_credentials")
			.param("client_id", "sales-agent")).andReturn().getResponse().getStatus()).isEqualTo(401);
		assertThat(this.mvc.perform(post("/oauth2/token").param("grant_type", "client_credentials")
			.with((r) -> {
				r.addHeader("Authorization", "Basic " + Base64.getEncoder()
					.encodeToString("sales-agent:secret".getBytes(StandardCharsets.UTF_8)));
				return r;
			})).andReturn().getResponse().getStatus()).isEqualTo(401);
	}

	@Test
	void exchangesOutsideTheChainAreRefused() throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		String salesActor = actorToken(SALES_AGENT, "sales-agent");
		String mcpActor = actorToken(INSURER_MCP, "insurer-mcp");

		// 事務サービスが、営業 AI エージェント宛ての A を替える
		assertThat(refusal(INSURER_MCP, "insurer-mcp", a, mcpActor, "insurer-backend"))
			.contains("subject_token is not addressed to the requester");
		// 営業 AI エージェントが、段を飛ばして保険会社のシステム宛てを求める
		assertThat(refusal(SALES_AGENT, "sales-agent", a, salesActor, "insurer-backend"))
			.contains("audience is not allowed for the requester");
		// actor_token がない
		assertThat(refusal(SALES_AGENT, "sales-agent", a, null, "insurer-mcp"))
			.contains("actor_token is not bound to the requester certificate");
		// actor_token が、いま示した証明書に結ばれていない
		assertThat(refusal(SALES_AGENT_OTHER_KEY, "sales-agent", a, salesActor, "insurer-mcp"))
			.contains("actor_token is not bound to the requester certificate");
		// 他人の actor_token を使う
		assertThat(refusal(SALES_AGENT, "sales-agent", a, mcpActor, "insurer-mcp"))
			.contains("actor_token is not bound to the requester certificate");
	}

	private String customerToken(ECKey dpopKey) throws Exception {
		String verifier = UUID.randomUUID() + "-" + UUID.randomUUID();
		MvcResult result = this.mvc
			.perform(post("/oauth2/token").param("grant_type", "authorization_code")
				.param("client_id", "customer-app")
				.param("code", authorizationCode(verifier))
				.param("redirect_uri", REDIRECT)
				.param("code_verifier", verifier)
				.header("DPoP", dpopProof(dpopKey)))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		Map<?, ?> body = this.json.readValue(result.getResponse().getContentAsString(), Map.class);
		assertThat(body.get("token_type")).isEqualTo("DPoP");
		return (String) body.get("access_token");
	}

	private String authorizationCode(String verifier) throws Exception {
		MvcResult result = this.mvc
			.perform(get(UriComponentsBuilder.fromPath("/oauth2/authorize")
				.queryParam("response_type", "code")
				.queryParam("client_id", "customer-app")
				.queryParam("scope", "apply")
				.queryParam("redirect_uri", REDIRECT)
				.queryParam("state", "s")
				.queryParam("code_challenge", challenge(verifier))
				.queryParam("code_challenge_method", "S256")
				.build()
				.toUriString()).with(user("alice")))
			.andReturn();
		String location = result.getResponse().getRedirectedUrl();
		assertThat(location).startsWith(REDIRECT);
		return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
	}

	private String actorToken(X509Certificate cert, String clientId) throws Exception {
		MvcResult result = clientCredentials(cert, clientId);
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return (String) this.json.readValue(result.getResponse().getContentAsString(), Map.class).get("access_token");
	}

	private MvcResult clientCredentials(X509Certificate cert, String clientId) throws Exception {
		return this.mvc
			.perform(post("/oauth2/token").param("grant_type", "client_credentials")
				.param("client_id", clientId)
				.with(x509(cert)))
			.andReturn();
	}

	private String exchange(X509Certificate cert, String clientId, String subject, String actor, String audience)
			throws Exception {
		MvcResult result = this.mvc.perform(exchangeRequest(cert, clientId, subject, actor, audience)).andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return (String) this.json.readValue(result.getResponse().getContentAsString(), Map.class).get("access_token");
	}

	private String refusal(X509Certificate cert, String clientId, String subject, String actor, String audience)
			throws Exception {
		MvcResult result = this.mvc.perform(exchangeRequest(cert, clientId, subject, actor, audience)).andReturn();
		assertThat(result.getResponse().getStatus()).isEqualTo(400);
		return result.getResponse().getContentAsString();
	}

	private static MockHttpServletRequestBuilder exchangeRequest(X509Certificate cert, String clientId,
			String subject, String actor, String audience) {
		MockHttpServletRequestBuilder request = post("/oauth2/token").param("grant_type", TOKEN_EXCHANGE)
			.param("client_id", clientId)
			.param("subject_token", subject)
			.param("subject_token_type", ACCESS_TOKEN_TYPE)
			.param("audience", audience)
			.with(x509(cert));
		if (actor != null) {
			request.param("actor_token", actor).param("actor_token_type", ACCESS_TOKEN_TYPE);
		}
		return request;
	}

	private static String dpopProof(ECKey key) throws Exception {
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

	private static Map<String, Object> claims(String jwt) throws Exception {
		SignedJWT parsed = SignedJWT.parse(jwt);
		assertThat(parsed.getHeader().getType().getType()).isEqualTo("at+jwt");
		return parsed.getJWTClaimsSet().toJSONObject();
	}

	private static Map<String, Object> cnf(Map<String, Object> claims) {
		return map(claims.get("cnf"));
	}

	/** 宛先が 1 つだけなら、JWT の aud は文字列になる。 */
	private static Object audience(Map<String, Object> claims) {
		Object aud = claims.get("aud");
		return (aud instanceof java.util.List<?> list && list.size() == 1) ? list.get(0) : aud;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> map(Object value) {
		return (Map<String, Object>) value;
	}

	private static String challenge(String verifier) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	private static String thumbprint(X509Certificate cert) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
