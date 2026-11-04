package jp.gekko11.insurerauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

/** 取決めの範囲、確認済みの属性、失効、有効性の問い合わせ、内部の受け口と、外せる防御（D3a〜D3f）を確かめる。 */
@Import(TestDefenses.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthFeaturesTest extends AuthTestSupport {

	private static final X509Certificate SALES = svid("sales-agent");

	private static final X509Certificate MCP = svid("insurer-mcp");

	private static final X509Certificate BACKEND = svid("insurer-backend");

	private static final X509Certificate OPERATOR = svid("operator");

	private static final X509Certificate AUDIT = svid("insurer-audit");

	private static final String AUDIT_REDIRECT = "http://127.0.0.1:4100/login/oauth2/code/insurer-auth";

	@AfterEach
	void restore() throws Exception {
		TestDefenses.OFF.clear();
		this.mvc.perform(post("/admin/clients/sales-agent/restore").with(x509(OPERATOR)));
	}

	@Test
	void tokenACarriesTermsAndVerifiedClaimsOnlyForVerifiedCustomers() throws Exception {
		Map<String, Object> alice = claims(customerToken(new ECKeyGenerator(Curve.P_256).generate(), "alice"));
		assertThat(terms(alice)).containsEntry("maxBenefit", 1200000L);
		assertThat(alice).containsKey("verified_claims");
		Map<String, Object> mallory = claims(customerToken(new ECKeyGenerator(Curve.P_256).generate(), "mallory"));
		assertThat(mallory).doesNotContainKey("verified_claims");
	}

	@Test
	void exchangeInheritsAndOnlyNarrowsTerms() throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		String wide = "[{\"type\":\"insurance_application\",\"kinds\":[\"annuity\",\"whole-life\"],\"maxBenefit\":9000000}]";
		Map<String, Object> b = claims(exchangeWithTerms(a, wide));
		assertThat(b).containsKey("verified_claims");
		assertThat(terms(b)).containsEntry("maxBenefit", 1200000L).containsEntry("kinds", List.of("annuity"));

		TestDefenses.OFF.add(Defenses.NARROW_TERMS);
		Map<String, Object> widened = claims(exchangeWithTerms(a, wide));
		assertThat(terms(widened)).containsEntry("maxBenefit", 9000000L);
	}

	@Test
	void revokedClientGetsNoTokenAndItsTokensBecomeInactive() throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		String b = exchange(SALES, "sales-agent", a, actorToken(SALES, "sales-agent"), "insurer-mcp");
		assertThat(introspect(b)).containsEntry("active", true);

		assertThat(this.mvc.perform(post("/admin/clients/sales-agent/revoke").with(x509(SALES)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(403);
		assertThat(this.mvc.perform(post("/admin/clients/sales-agent/revoke").with(x509(OPERATOR)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);

		assertThat(clientCredentials(SALES, "sales-agent").getResponse().getStatus()).isEqualTo(401);
		assertThat(introspect(b)).containsEntry("active", false);
	}

	@Test
	void onlyTheBackendReadsPasskeys() throws Exception {
		assertThat(this.mvc.perform(get("/internal/passkeys/alice").with(x509(MCP))).andReturn().getResponse().getStatus())
			.isEqualTo(403);
		assertThat(this.mvc.perform(get("/internal/passkeys/alice").with(x509(BACKEND)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
	}

	@Test
	void issuanceAndExchangeAreRecordedWithChainedJti(CapturedOutput output) throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		String b = exchange(SALES, "sales-agent", a, actorToken(SALES, "sales-agent"), "insurer-mcp");
		String aJti = (String) claims(a).get("jti");
		String bJti = (String) claims(b).get("jti");
		// ログインで出した A は issue、交換で出した B は exchange として、A の jti を元にした記録が残る
		assertThat(output.getOut()).contains("\"kind\":\"issue\"").contains("\"jti\":\"" + aJti + "\"");
		assertThat(output.getOut()).contains("\"kind\":\"exchange\"").contains("\"jti\":\"" + bJti + "\"")
			.contains("\"from_jti\":\"" + aJti + "\"");
		// トークンそのものは書かない
		assertThat(output.getOut()).doesNotContain(a).doesNotContain(b);
	}

	@Test
	void auditServiceLogsInWithItsSvidAndPkceAndTheIdTokenCarriesTheRole() throws Exception {
		assertThat(auditIdToken("kansa", AUDIT).get("roles")).isEqualTo(List.of("AUDITOR"));
		assertThat(auditIdToken("alice", AUDIT).get("roles")).isEqualTo(List.of("CUSTOMER"));
		// 監査サービスの SVID でなければ、認可コードを替えられない
		assertThat(auditTokenRequest("kansa", SALES).getResponse().getStatus()).isEqualTo(401);
	}

	private Map<String, Object> auditIdToken(String user, X509Certificate cert) throws Exception {
		MvcResult result = auditTokenRequest(user, cert);
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		String idToken = (String) this.json.readValue(result.getResponse().getContentAsString(), Map.class).get("id_token");
		return SignedJWT.parse(idToken).getJWTClaimsSet().toJSONObject();
	}

	/** 監査サービスの認可コードの流れ。クライアント認証は SVID の mTLS で、PKCE も使う。 */
	private MvcResult auditTokenRequest(String user, X509Certificate cert) throws Exception {
		String verifier = java.util.UUID.randomUUID() + "-" + java.util.UUID.randomUUID();
		MvcResult authorized = this.mvc
			.perform(get(UriComponentsBuilder.fromPath("/oauth2/authorize")
				.queryParam("response_type", "code")
				.queryParam("client_id", "insurer-audit")
				.queryParam("scope", "openid")
				.queryParam("redirect_uri", AUDIT_REDIRECT)
				.queryParam("state", "s")
				.queryParam("nonce", "n")
				.queryParam("code_challenge", challenge(verifier))
				.queryParam("code_challenge_method", "S256")
				.build()
				.encode()
				.toUri()).with(user(user).roles("kansa".equals(user) ? "AUDITOR" : "CUSTOMER")))
			.andReturn();
		String code = UriComponentsBuilder.fromUriString(authorized.getResponse().getRedirectedUrl())
			.build()
			.getQueryParams()
			.getFirst("code");
		return this.mvc
			.perform(post("/oauth2/token").param("grant_type", "authorization_code")
				.param("client_id", "insurer-audit")
				.param("code", code)
				.param("redirect_uri", AUDIT_REDIRECT)
				.param("code_verifier", verifier)
				.with(x509(cert)))
			.andReturn();
	}

	@Test
	void signOutWithAnUnknownIdTokenReturnsOnlyToARegisteredPage() throws Exception {
		// 再起動の前の ID トークンなどで確かめられなくても、登録された戻り先へ戻す
		MvcResult back = this.mvc.perform(get("/connect/logout").param("client_id", "customer-app")
			.param("post_logout_redirect_uri", "http://127.0.0.1:4000/")
			.param("id_token_hint", "unknown")).andReturn();
		assertThat(back.getResponse().getRedirectedUrl()).isEqualTo("http://127.0.0.1:4000/");
		MvcResult noHint = this.mvc.perform(get("/connect/logout").param("client_id", "insurer-audit")
			.param("post_logout_redirect_uri", "http://127.0.0.1:4100/")).andReturn();
		assertThat(noHint.getResponse().getRedirectedUrl()).isEqualTo("http://127.0.0.1:4100/");
		// 登録にない宛先へは戻さない
		MvcResult other = this.mvc.perform(get("/connect/logout").param("client_id", "customer-app")
			.param("post_logout_redirect_uri", "http://attacker.invalid/")
			.param("id_token_hint", "unknown")).andReturn();
		assertThat(other.getResponse().getStatus()).isEqualTo(400);
		assertThat(other.getResponse().getRedirectedUrl()).isNull();
	}

	@Test
	void loggedInCustomerListsOnlyOwnPasskeyIds() throws Exception {
		// ログインしていなければ、一覧は出ない
		assertThat(this.mvc.perform(get("/passkeys/mine")).andReturn().getResponse().getStatus()).isNotEqualTo(200);
		// ログインした本人には、本人の一覧（まだ登録がなければ空）だけを返す
		assertThat(this.mvc.perform(get("/passkeys/mine").with(user("alice"))).andReturn().getResponse().getContentAsString())
			.isEqualTo("{\"credentialIds\":[]}");
	}

	@Test
	void onlyTheBackendReadsContacts() throws Exception {
		assertThat(this.mvc.perform(get("/internal/contacts/alice").with(x509(MCP))).andReturn().getResponse().getStatus())
			.isEqualTo(403);
		// 受信箱を登録していない顧客には、連絡先がない
		assertThat(this.mvc.perform(get("/internal/contacts/alice").with(x509(BACKEND)))
			.andReturn()
			.getResponse()
			.getContentAsString()).isEqualTo("{\"inboxes\":[]}");
	}

	@Test
	void weakIssuanceAppearsOnlyWhenDefensesAreOff() throws Exception {
		TestDefenses.OFF.addAll(List.of(Defenses.AUD_ONE, Defenses.SHORT_TTL, Defenses.KEEP_ACT));
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		Map<String, Object> ac = claims(a);
		assertThat(ac.get("aud")).isEqualTo(List.of("sales-agent", "insurer-mcp", "insurer-backend"));
		assertThat(((Number) ac.get("exp")).longValue()).isGreaterThan(Instant.now().plusSeconds(3600).getEpochSecond());
		Map<String, Object> b = claims(exchange(SALES, "sales-agent", a, actorToken(SALES, "sales-agent"), "insurer-mcp"));
		assertThat(b).doesNotContainKey("act");
	}

	@Test
	void skippingTheMiddleHopNeedsD3fOff() throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		String actor = actorToken(SALES, "sales-agent");
		assertThat(this.mvc.perform(exchangeRequest(SALES, "sales-agent", a, actor, "insurer-backend"))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(400);
		TestDefenses.OFF.add(Defenses.FIXED_TARGET);
		assertThat(exchange(SALES, "sales-agent", a, actor, "insurer-backend")).isNotBlank();
	}

	private String exchangeWithTerms(String a, String terms) throws Exception {
		MvcResult result = this.mvc
			.perform(exchangeRequest(SALES, "sales-agent", a, actorToken(SALES, "sales-agent"), "insurer-mcp")
				.param("authorization_details", terms))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return (String) this.json.readValue(result.getResponse().getContentAsString(), Map.class).get("access_token");
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> introspect(String token) throws Exception {
		MvcResult result = this.mvc
			.perform(post("/oauth2/introspect").param("token", token)
				.param("client_id", "insurer-backend")
				.with(x509(BACKEND)))
			.andReturn();
		assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
		return this.json.readValue(result.getResponse().getContentAsString(), Map.class);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> terms(Map<String, Object> claims) {
		return ((List<Map<String, Object>>) claims.get("authorization_details")).get(0);
	}


}
