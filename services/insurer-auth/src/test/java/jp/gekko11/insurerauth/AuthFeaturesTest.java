package jp.gekko11.insurerauth;

import static org.assertj.core.api.Assertions.assertThat;
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
import org.springframework.test.web.servlet.MvcResult;

/** 取決めの範囲、確認済みの属性、失効、有効性の問い合わせ、内部の受け口と、外せる防御（D3a〜D3f）を確かめる。 */
@Import(TestDefenses.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthFeaturesTest extends AuthTestSupport {

	private static final X509Certificate SALES = svid("sales-agent");

	private static final X509Certificate MCP = svid("insurer-mcp");

	private static final X509Certificate BACKEND = svid("insurer-backend");

	private static final X509Certificate OPERATOR = svid("operator");

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
		assertThat(this.mvc.perform(get("/internal/passkeys/alice").with(x509(MCP))).andReturn().getResponse().getStatus())
			.isEqualTo(403);
		assertThat(this.mvc.perform(get("/internal/passkeys/alice").with(x509(BACKEND)))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
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
	void passkeysNeedTheTokenPWithItsDpopProof() throws Exception {
		ECKey key = new ECKeyGenerator(Curve.P_256).generate();
		String uri = "http://localhost/passkeys/mine";
		String p = loginToken(LOGIN_KEY, "at+jwt", aClaims(key, "alice").audience("insurer-auth").build());
		String a = customerToken(key);
		// トークンがなければ、一覧は出ない
		assertThat(mine(null, null)).isEqualTo(401);
		// proof のない Bearer は受けない。盗んだ P は使えない
		assertThat(this.mvc.perform(get("/passkeys/mine").header("Authorization", "Bearer " + p))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(401);
		// 別の鍵の proof
		assertThat(mine(p, dpopProof(new ECKeyGenerator(Curve.P_256).generate(), "GET", uri, p))).isEqualTo(401);
		// 宛先の違う A
		assertThat(mine(a, dpopProof(key, "GET", uri, a))).isEqualTo(401);
		// 本人には、本人の一覧（まだ登録がなければ空）だけを返す
		assertThat(this.mvc
			.perform(get("/passkeys/mine").header("Authorization", "DPoP " + p).header("DPoP", dpopProof(key, "GET", uri, p)))
			.andReturn()
			.getResponse()
			.getContentAsString()).isEqualTo("{\"credentialIds\":[]}");
	}

	private int mine(String token, String proof) throws Exception {
		var request = get("/passkeys/mine");
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
