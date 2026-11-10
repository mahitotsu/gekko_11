package jp.gekko11.insureraudit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** 監査の画面は、役割が監査の者にだけ見せる。ログインしていなければ、認可サーバーのログインへ送る。 */
@SpringBootTest
@AutoConfigureMockMvc
class AuditAccessTest {

	@Autowired
	MockMvc mvc;

	@MockitoBean
	RecordSource source;

	@Autowired
	ClientRegistrationRepository clients;

	@Test
	void notLoggedInGoesToTheLoginServerWithPkce() throws Exception {
		MvcResult first = this.mvc.perform(get("/api/contracts")).andReturn();
		assertThat(first.getResponse().getRedirectedUrl()).endsWith("/oauth2/authorization/insurer-login");
		MvcResult authorize = this.mvc.perform(get("/oauth2/authorization/insurer-login")).andReturn();
		assertThat(authorize.getResponse().getRedirectedUrl()).startsWith("http://login.secure.localhost:8081/realms/insurer/protocol/openid-connect/auth?")
			.contains("code_challenge=")
			.contains("redirect_uri=http://audit.secure.localhost:8081/login/oauth2/code/insurer-login");
	}

	@Test
	void contractPageStartsWithWhatWasCompared() throws Exception {
		ReconcilerTest.Memory records = ReconcilerTest.regular(Map.of("id", "fixed-60", "name", "確定年金"), Reconciler.ROUTE,
				Map.of("sub", "insurer-mcp", "act", Map.of("sub", "sales-agent")));
		given(this.source.selfReported()).willReturn(records.self);
		given(this.source.search(any())).willAnswer((i) -> records.search(i.getArgument(0)));
		String page = this.mvc
			.perform(get("/contracts/n-1").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_AUDITOR"))))
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertThat(page).contains("食い違いなし", "第三者の記録との比較", "事務サービス ← 営業 AI エージェント", "fixed-60");
		// 冒頭の表に、何と何を比べたかが出て、詳しい記録はその後に続く
		assertThat(page.indexOf("何と何を比べたか")).isLessThan(page.indexOf("第三者の記録との比較"));
		assertThat(page.indexOf("比べた値")).isLessThan(page.indexOf("保険会社のシステムの契約の記録（Loki）"));
		assertThat(page).contains("保険会社のシステムの自己申告 ↔ Loki の契約の記録").doesNotContain("data-testid=\"mismatches\"");
	}

	@Test
	void signOutAlsoEndsTheLoginAtTheLoginServer() throws Exception {
		MvcResult result = this.mvc
			.perform(post("/logout").with(csrf())
				.with(oidcLogin().clientRegistration(this.clients.findByRegistrationId("insurer-login"))))
			.andReturn();
		assertThat(result.getResponse().getRedirectedUrl()).startsWith("http://login.secure.localhost:8081/realms/insurer/protocol/openid-connect/logout?")
			.contains("id_token_hint=")
			.contains("post_logout_redirect_uri=http://audit.secure.localhost:8081/");
	}

	@Test
	void onlyAuditorsSeeTheRecords() throws Exception {
		given(this.source.selfReported()).willReturn(List.of());
		given(this.source.contracts()).willReturn(List.of());
		assertThat(this.mvc
			.perform(get("/api/contracts").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_AUDITOR"))))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(200);
		assertThat(this.mvc
			.perform(get("/api/contracts").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_CUSTOMER"))))
			.andReturn()
			.getResponse()
			.getStatus()).isEqualTo(403);
	}

	@Test
	void stylesAreServedWithoutLoginAndThePageShowsTheNamespace() throws Exception {
		// ログインの前と 403 の画面でも見た目が崩れないよう、CSS とスクリプトは誰にでも配る（D-48）
		for (String path : List.of("/webjars/bootstrap/dist/css/bootstrap.min.css", "/assets/audit.css", "/assets/theme.js")) {
			assertThat(this.mvc.perform(get(path)).andReturn().getResponse().getStatus()).as(path).isEqualTo(200);
		}
		given(this.source.selfReported()).willReturn(List.of());
		given(this.source.contracts()).willReturn(List.of());
		String page = this.mvc.perform(get("/").with(oidcLogin().authorities(new SimpleGrantedAuthority("ROLE_AUDITOR"))))
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertThat(page).contains("data-testid=\"namespace\"", "名前空間: secure");
	}

}
