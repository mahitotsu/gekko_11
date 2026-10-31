package jp.gekko11.insurerbackend;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 保険会社のシステムの内容の確かめ（D9、D11〜D18）。トークンは token-guard が確かめた後の形（x-auth-claims）で渡す。
 * 署名は、テスト用の認証器で作り、本物の検証に通す。
 */
@SpringBootTest(properties = { "gekko.rp-id=customer-app.test", "gekko.origins=https://customer-app.test" })
@AutoConfigureMockMvc
@Import(TestBackendConfig.class)
class ApplicationTest {

	private static final String TERMS_OK = "fixed,lifetime";

	@Autowired
	MockMvc mvc;

	@Autowired
	Store store;

	private final ObjectMapper json = new ObjectMapper();

	private SoftAuthenticator alice;

	@BeforeEach
	void register() throws Exception {
		this.alice = new SoftAuthenticator("customer-app.test", "https://customer-app.test");
		TestBackendConfig.PASSKEYS.put("alice", List.of(this.alice.registered()));
	}

	@AfterEach
	void reset() {
		TestBackendConfig.OFF.clear();
		TestBackendConfig.PASSKEYS.clear();
	}

	@Test
	void signedApplicationWithinTermsBecomesADerivedContract() throws Exception {
		MvcResult result = submit(claims("alice", true), prepare("alice", "fixed-120", Map.of()));
		assertThat(result.getResponse().getStatus()).as(body(result)).isEqualTo(200);
		Store.ContractRecord record = this.store.contracts.get(this.store.contracts.size() - 1);
		assertThat(record.by()).containsExactly("insurer-mcp", "sales-agent");
		assertThat(record.contract().get("contractId")).asString().startsWith("C-");
		assertThat(this.store.outbox.get(this.store.outbox.size() - 1).to()).isEqualTo("/notices?customer=alice");
	}

	@Test
	void customerComesFromTheTokenNotFromTheAgent() throws Exception {
		MvcResult offer = this.mvc.perform(post("/offers").header("x-auth-claims", claims("alice", true))
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"for_user\":\"bob\"}")).andReturn();
		assertThat(read(offer).get("offerSet").toString()).contains("customer=alice");

		TestBackendConfig.OFF.put(Defenses.CUSTOMER_FROM_SUB, "off");
		offer = this.mvc.perform(post("/offers").header("x-auth-claims", claims("alice", true))
			.contentType(MediaType.APPLICATION_JSON)
			.content("{\"for_user\":\"bob\"}")).andReturn();
		assertThat(read(offer).get("offerSet").toString()).contains("customer=bob");
	}

	@Test
	void verifiedClaimsComeFromTheToken() throws Exception {
		Map<String, Object> body = prepare("alice", "fixed-60", Map.of());
		body.put("verified_claims", Map.of("verification", Map.of("method", "agent says so")));
		assertThat(submit(claims("alice", false), body).getResponse().getStatus()).isEqualTo(403);
		TestBackendConfig.OFF.put(Defenses.VERIFIED_FROM_TOKEN, "off");
		assertThat(submit(claims("alice", false), prepare("alice", "fixed-60", Map.of("verified_claims",
				Map.of("verification", Map.of("method", "agent says so"))))).getResponse().getStatus()).isEqualTo(200);
	}

	@Test
	void planOutsideTheSignedOfferIsRefused() throws Exception {
		Map<String, Object> forged = new HashMap<>(Store.CATALOG.get(0));
		forged.put("monthly", 1);
		MvcResult result = submit(claims("alice", true), prepare("alice", forged, Map.of()));
		assertThat(body(result)).contains("提示にない案");
		TestBackendConfig.OFF.put(Defenses.OFFER_SIGNATURE, "off");
		assertThat(submit(claims("alice", true), prepare("alice", forged, Map.of())).getResponse().getStatus())
			.isEqualTo(200);
	}

	@SuppressWarnings("unchecked")
	@Test
	void applicationChangedAfterSigningIsRefused() throws Exception {
		Map<String, Object> body = prepare("alice", "fixed-60", Map.of());
		Map<String, Object> application = new LinkedHashMap<>((Map<String, Object>) body.get("application"));
		application.put("plan", Store.CATALOG.get(3));
		body.put("application", application);
		assertThat(body(submit(claims("alice", true), body))).contains("申込みの署名の照合");

		TestBackendConfig.OFF.put(Defenses.PASSKEY_SEAL, "mtls-only");
		assertThat(submit(claims("alice", true, "spiffe://gekko11.internal/ns/secure/sa/insurer-mcp"),
				prepare("alice", "fixed-60", Map.of())).getResponse().getStatus()).isEqualTo(200);
	}

	@SuppressWarnings("unchecked")
	@Test
	void applicationMustChainToTheSignedIntent() throws Exception {
		Map<String, Object> body = prepare("alice", "fixed-60", Map.of());
		Map<String, Object> application = new LinkedHashMap<>((Map<String, Object>) body.get("application"));
		application.put("intentSignature", "not-the-intent");
		body.put("application", application);
		body.put("assertion", this.alice.sign(Canonical.challengeOf(application)));
		assertThat(body(submit(claims("alice", true), body))).contains("意向確認と申込みが対応");
	}

	@Test
	void planBeyondTheTermsIsRefused() throws Exception {
		assertThat(body(submit(claims("alice", true), prepare("alice", "life-240", Map.of()))))
			.contains("年金の年額の上限以内");
		TestBackendConfig.OFF.put(Defenses.TERMS_RANGE, "off");
		assertThat(submit(claims("alice", true), prepare("alice", "life-240", Map.of())).getResponse().getStatus())
			.isEqualTo(200);
	}

	@Test
	void sameApplicationIsAcceptedOnce() throws Exception {
		Map<String, Object> body = prepare("alice", "fixed-60", Map.of());
		assertThat(submit(claims("alice", true), body).getResponse().getStatus()).isEqualTo(200);
		assertThat(submit(claims("alice", true), body).getResponse().getStatus()).isEqualTo(409);
	}

	@Test
	void recordAndContactIgnoreWhatTheAgentAdds() throws Exception {
		Map<String, Object> extras = Map.of("contractEntry", Map.of("plan", Store.CATALOG.get(3)), "contact",
				"http://attacker.invalid/notices");
		assertThat(submit(claims("alice", true), prepare("alice", "fixed-60", extras)).getResponse().getStatus())
			.isEqualTo(200);
		assertThat(this.store.contracts.get(this.store.contracts.size() - 1).contract().get("plan").toString())
			.contains("fixed-60");
		assertThat(this.store.outbox.get(this.store.outbox.size() - 1).to()).isEqualTo("/notices?customer=alice");

		TestBackendConfig.OFF.put(Defenses.DERIVE_RECORD, "off");
		TestBackendConfig.OFF.put(Defenses.REGISTERED_CONTACT, "off");
		submit(claims("alice", true), prepare("alice", "fixed-60", extras));
		assertThat(this.store.contracts.get(this.store.contracts.size() - 1).contract().get("plan").toString())
			.contains("life-240");
		assertThat(this.store.outbox.get(this.store.outbox.size() - 1).to()).isEqualTo("http://attacker.invalid/notices");
	}

	@Test
	void auditRecordsAreOnlyForTheAuditor() throws Exception {
		assertThat(this.mvc.perform(get("/audit/records")).andReturn().getResponse().getStatus()).isEqualTo(403);
		assertThat(this.mvc
			.perform(get("/audit/records").header("x-forwarded-client-cert",
					"Hash=ab;URI=spiffe://gekko11.internal/ns/secure/sa/auditor"))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
	}

	// ---- 手順 ----

	private Map<String, Object> prepare(String customer, String planId, Map<String, Object> extras) throws Exception {
		Map<String, Object> plan = Store.CATALOG.stream().filter((p) -> p.get("id").equals(planId)).findFirst().orElseThrow();
		return prepare(customer, plan, extras);
	}

	/** 顧客の手順: 提示を受け取り、意向確認に署名し、その署名の値を含めた申込みに署名する（3 章の 2〜3 段）。 */
	@SuppressWarnings("unchecked")
	private Map<String, Object> prepare(String customer, Map<String, Object> plan, Map<String, Object> extras)
			throws Exception {
		Map<String, Object> offer = read(this.mvc.perform(post("/offers").header("x-auth-claims", claims(customer, true)))
			.andReturn());
		Map<String, Object> intent = new LinkedHashMap<>();
		intent.put("customer", customer);
		intent.put("offerSetId", offer.get("offerSetId"));
		intent.put("planId", plan.get("id"));
		intent.put("wish", "老後の生活費に備えたい");
		intent.put("nonce", offer.get("nonce"));
		intent.put("expiresAt", offer.get("expiresAt"));
		Map<String, Object> intentAssertion = this.alice.sign(Canonical.challengeOf(intent));
		Map<String, Object> application = new LinkedHashMap<>();
		application.put("customer", customer);
		application.put("plan", plan);
		application.put("offerSetId", offer.get("offerSetId"));
		application.put("intentSignature", ((Map<String, Object>) intentAssertion.get("response")).get("signature"));
		application.put("nonce", offer.get("nonce"));
		application.put("expiresAt", offer.get("expiresAt"));
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("offerJws", offer.get("offerJws"));
		body.put("intent", intent);
		body.put("intentAssertion", intentAssertion);
		body.put("application", application);
		body.put("assertion", this.alice.sign(Canonical.challengeOf(application)));
		body.putAll(extras);
		return body;
	}

	private MvcResult submit(String claims, Map<String, Object> body) throws Exception {
		return this.mvc.perform(post("/applications").header("x-auth-claims", claims)
			.contentType(MediaType.APPLICATION_JSON)
			.content(this.json.writeValueAsString(body))).andReturn();
	}

	private String claims(String sub, boolean verified) throws Exception {
		return claims(sub, verified, "spiffe://gekko11.internal/ns/secure/sa/insurer-mcp");
	}

	/** token-guard が渡す形の、確かめた主張。C の形（act は事務サービス、その内側に営業 AI エージェント）。 */
	private String claims(String sub, boolean verified, String peer) throws Exception {
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("sub", sub);
		claims.put("scope", List.of("apply"));
		claims.put("act", Map.of("sub", "insurer-mcp", "act", Map.of("sub", "sales-agent")));
		claims.put("authorization_details", List.of(Map.of("type", "insurance_application", "kinds",
				List.of(TERMS_OK.split(",")), "maxBenefit", 1_200_000)));
		if (verified) {
			claims.put("verified_claims", Map.of("verification", Map.of("trust_framework", "jp_aml", "method", "対面")));
		}
		byte[] summary = this.json.writeValueAsBytes(Map.of("claims", claims, "peer", Map.of("spiffeId", peer)));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(summary);
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> read(MvcResult result) throws Exception {
		return this.json.readValue(result.getResponse().getContentAsString(), Map.class);
	}

	private static String body(MvcResult result) throws Exception {
		return result.getResponse().getContentAsString();
	}

}
