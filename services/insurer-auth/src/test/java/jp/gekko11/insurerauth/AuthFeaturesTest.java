package jp.gekko11.insurerauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MvcResult;

/** 取決めの範囲、確認済みの属性、失効、有効性の問い合わせ、内部の受け口と、外せる防御（G3a〜G3f）を確かめる。 */
@Import(TestDefenses.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthFeaturesTest extends AuthTestSupport {

	private static final X509Certificate SALES = svid("sales-agent");

	private static final X509Certificate MCP = svid("insurer-mcp");

	private static final X509Certificate BACKEND = svid("insurer-backend");

	private static final X509Certificate OPERATOR = svid("operator");

	/** passkey の公開鍵は、ログインサーバーの管理の API から読む。単体テストでは、ログインサーバーの代わりを置く。 */
	@MockitoBean
	private LoginDirectory directory;

	@AfterEach
	void restore() throws Exception {
		TestDefenses.OFF.clear();
		this.mvc.perform(post("/admin/clients/sales-agent/restore").with(x509(OPERATOR)));
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
		given(this.directory.keysOf("alice")).willReturn(List.of(Map.of("id", "cred", "coseKey", "key")));
		assertThat(this.mvc.perform(get("/internal/passkeys/alice").with(x509(MCP))).andReturn().getResponse().getStatus())
			.isEqualTo(403);
		assertThat(this.mvc.perform(get("/internal/passkeys/alice").with(x509(BACKEND)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
		// ログインサーバーから読めなければ、空の一覧ではなく、失敗として返す（署名を確かめないまま通さない）
		given(this.directory.keysOf("bob")).willThrow(new IllegalStateException("login server is down"));
		assertThat(this.mvc.perform(get("/internal/passkeys/bob").with(x509(BACKEND)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(502);
	}

	@Test
	void exchangeIsRecordedWithChainedJti(CapturedOutput output) throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());
		String b = exchange(SALES, "sales-agent", a, actorToken(SALES, "sales-agent"), "insurer-mcp");
		String aJti = (String) claims(a).get("jti");
		String bJti = (String) claims(b).get("jti");
		// 交換で出した B は exchange として、A の jti を元にした記録が残る（A の issue は、ログインサーバーが書く）
		assertThat(output.getOut()).contains("\"kind\":\"exchange\"").contains("\"jti\":\"" + bJti + "\"")
			.contains("\"from_jti\":\"" + aJti + "\"");
		// トークンそのものは書かない
		assertThat(output.getOut()).doesNotContain(a).doesNotContain(b);
	}

	@Test
	void contactsNeedTheTokenPWithItsDpopProof() throws Exception {
		ECKey key = new ECKeyGenerator(Curve.P_256).generate();
		String uri = "http://localhost/contacts/mine";
		String p = loginToken(LOGIN_KEY, "at+jwt", aClaims(key, "alice").audience("insurer-auth").build());
		String a = customerToken(key);
		// トークンがなければ、一覧は出ない
		assertThat(mine(null, null)).isEqualTo(401);
		// proof のない Bearer は受けない。盗んだ P は使えない
		assertThat(this.mvc.perform(get("/contacts/mine").header("Authorization", "Bearer " + p))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(401);
		// 別の鍵の proof
		assertThat(mine(p, dpopProof(new ECKeyGenerator(Curve.P_256).generate(), "GET", uri, p))).isEqualTo(401);
		// 宛先の違う A
		assertThat(mine(a, dpopProof(key, "GET", uri, a))).isEqualTo(401);
		// 本人には、本人の一覧（まだ登録がなければ空）だけを返す
		assertThat(this.mvc
			.perform(get("/contacts/mine").header("Authorization", "DPoP " + p).header("DPoP", dpopProof(key, "GET", uri, p)))
			.andReturn()
			.getResponse()
			.getContentAsString()).isEqualTo("{\"inboxes\":[]}");
		// 本人は、P で受信箱を登録でき、一覧に載る（顧客のアプリの BFF が、ログインの直後に送る。D-26）
		// ほかのテストが alice の一覧を空と見るので、別の利用者で確かめる
		String inbox = "AAAAAAAAAAAAAAAAAAAAAA";
		String carol = loginToken(LOGIN_KEY, "at+jwt", aClaims(key, "carol").audience("insurer-auth").build());
		assertThat(this.mvc
			.perform(post("/contacts/inbox").header("Authorization", "DPoP " + carol)
				.header("DPoP", dpopProof(key, "POST", "http://localhost/contacts/inbox", carol))
				.contentType("application/json")
				.content("{\"inbox\":\"" + inbox + "\"}"))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
		assertThat(this.mvc
			.perform(get("/contacts/mine").header("Authorization", "DPoP " + carol).header("DPoP", dpopProof(key, "GET", uri, carol)))
			.andReturn()
			.getResponse()
			.getContentAsString()).contains(inbox);
	}

	@Test
	void ownPasskeyListNeedsTheTokenPWithItsDpopProof() throws Exception {
		ECKey key = new ECKeyGenerator(Curve.P_256).generate();
		String uri = "http://localhost/passkeys/mine";
		String p = loginToken(LOGIN_KEY, "at+jwt", aClaims(key, "alice").audience("insurer-auth").build());
		given(this.directory.listOf("alice")).willReturn(Map.of("userHandle", "YWxpY2U", "passkeys", List.of(Map.of("id", "cred", "label", "x", "created", 1))));
		// トークンがなければ、一覧は出ない。本人には、本人の一覧だけを返す（公開鍵は含まない。D-43）
		assertThat(this.mvc.perform(get("/passkeys/mine")).andReturn().getResponse().getStatus()).isEqualTo(401);
		String body = this.mvc
			.perform(get("/passkeys/mine").header("Authorization", "DPoP " + p).header("DPoP", dpopProof(key, "GET", uri, p)))
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertThat(body).contains("\"userHandle\":\"YWxpY2U\"").contains("\"id\":\"cred\"").doesNotContain("coseKey");
	}

	private int mine(String token, String proof) throws Exception {
		var request = get("/contacts/mine");
		if (token != null) {
			request.header("Authorization", "DPoP " + token).header("DPoP", proof);
		}
		return this.mvc.perform(request).andReturn().getResponse().getStatus();
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
		Map<String, Object> b = claims(exchange(SALES, "sales-agent", a, actorToken(SALES, "sales-agent"), "insurer-mcp"));
		assertThat(b.get("aud")).isEqualTo(List.of("sales-agent", "insurer-mcp", "insurer-backend"));
		assertThat(((Number) b.get("exp")).longValue()).isGreaterThan(Instant.now().plusSeconds(3600).getEpochSecond());
		assertThat(b).doesNotContainKey("act");
	}

	@Test
	void forgedTokenAIsExchangedOnlyWhenD28IsOff() throws Exception {
		ECKey key = new ECKeyGenerator(Curve.P_256).generate();
		String forged = loginToken(rsaKey(), "at+jwt", aClaims(key, "bob").build());
		String actor = actorToken(SALES, "sales-agent");
		assertThat(refusal(SALES, "sales-agent", forged, actor, "insurer-mcp")).contains("subject_token could not be verified");
		TestDefenses.OFF.add(Defenses.VERIFY_SUBJECT);
		assertThat(claims(exchange(SALES, "sales-agent", forged, actor, "insurer-mcp")).get("sub")).isEqualTo("bob");
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
