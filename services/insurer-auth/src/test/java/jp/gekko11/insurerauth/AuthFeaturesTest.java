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
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MvcResult;

/** 取決めの範囲、確認済みの属性、失効、有効性の問い合わせ、内部の受け口と、外せる防御（D3a〜D3f）を確かめる。 */
@Import(TestDefenses.class)
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
