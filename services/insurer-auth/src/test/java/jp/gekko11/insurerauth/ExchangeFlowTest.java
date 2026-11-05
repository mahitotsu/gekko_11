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
class ExchangeFlowTest extends AuthTestSupport {

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

	@Test
	void tokenAFromTheLoginServerIsExchangedOnlyWhenVerified() throws Exception {
		ECKey dpopKey = new ECKeyGenerator(Curve.P_256).generate();
		String actor = actorToken(SALES_AGENT, "sales-agent");
		JWTClaimsSet good = aClaims(dpopKey, "alice").build();

		assertThat(exchange(SALES_AGENT, "sales-agent", loginToken(LOGIN_KEY, "at+jwt", good), actor, "insurer-mcp"))
			.isNotBlank();

		// 別の鍵で、発行者を名乗る
		assertThat(refusal(SALES_AGENT, "sales-agent", loginToken(rsaKey(), "at+jwt", good), actor, "insurer-mcp"))
			.contains("subject_token could not be verified");
		// 別の発行者
		JWTClaimsSet otherIssuer = aClaims(dpopKey, "alice").issuer("http://other.test").build();
		assertThat(refusal(SALES_AGENT, "sales-agent", loginToken(LOGIN_KEY, "at+jwt", otherIssuer), actor, "insurer-mcp"))
			.contains("subject_token could not be verified");
		// 種類が違う（ID トークンなど）
		assertThat(refusal(SALES_AGENT, "sales-agent", loginToken(LOGIN_KEY, "JWT", good), actor, "insurer-mcp"))
			.contains("subject_token could not be verified");
		// 期限切れ
		JWTClaimsSet expired = aClaims(dpopKey, "alice").expirationTime(new Date(System.currentTimeMillis() - 1000)).build();
		assertThat(refusal(SALES_AGENT, "sales-agent", loginToken(LOGIN_KEY, "at+jwt", expired), actor, "insurer-mcp"))
			.contains("subject_token could not be verified");
		// 代理の認可がない
		JWTClaimsSet noMayAct = aClaims(dpopKey, "alice").claim("may_act", null).build();
		assertThat(refusal(SALES_AGENT, "sales-agent", loginToken(LOGIN_KEY, "at+jwt", noMayAct), actor, "insurer-mcp"))
			.contains("subject_token is not a token A");
		// 代理に認められた者が違う
		JWTClaimsSet otherActor = aClaims(dpopKey, "alice")
			.claim("may_act", Map.of("iss", "http://localhost", "sub", "insurer-mcp"))
			.build();
		refusal(SALES_AGENT, "sales-agent", loginToken(LOGIN_KEY, "at+jwt", otherActor), actor, "insurer-mcp");
	}

	@Test
	void exchangesRebindToTheRequesterCertificateAndNestAct() throws Exception {
		String a = customerToken(new ECKeyGenerator(Curve.P_256).generate());

		String b = exchange(SALES_AGENT, "sales-agent", a, actorToken(SALES_AGENT, "sales-agent"), "insurer-mcp");
		Map<String, Object> bc = claims(b);
		assertThat(bc.get("sub")).isEqualTo("alice");
		assertThat(bc.get("iss")).isEqualTo("http://localhost");
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

}
