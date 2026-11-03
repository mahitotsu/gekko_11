package jp.gekko11.insureraudit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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

	@Test
	void notLoggedInGoesToTheAuthorizationServerWithPkce() throws Exception {
		MvcResult first = this.mvc.perform(get("/api/contracts")).andReturn();
		assertThat(first.getResponse().getRedirectedUrl()).endsWith("/oauth2/authorization/insurer-auth");
		MvcResult authorize = this.mvc.perform(get("/oauth2/authorization/insurer-auth")).andReturn();
		assertThat(authorize.getResponse().getRedirectedUrl()).startsWith("http://auth.secure.localhost:8081/oauth2/authorize?")
			.contains("code_challenge=")
			.contains("redirect_uri=http://audit.secure.localhost:8081/login/oauth2/code/insurer-auth");
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

}
