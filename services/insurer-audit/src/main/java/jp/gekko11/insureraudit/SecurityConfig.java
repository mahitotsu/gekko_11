package jp.gekko11.insureraudit;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.endpoint.DefaultOAuth2TokenRequestParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 監査の担当は、認可サーバーにログインする（D-31）。監査サービスは、OpenID Connect のクライアントで、
 * 認可コードと PKCE を使い、クライアント認証は SVID の mTLS（tls_client_auth。D-7）である。
 * ブラウザは公開名の認可サーバーへ行き、トークンと公開鍵は、Envoy の出口（内部の名前）から取る。ID トークンの iss は、公開名で確かめる。
 * 画面と記録は、役割が監査の者にだけ見せる。全ての顧客の契約と会話が出るからである。
 */
@Configuration
class SecurityConfig {

	static final String REGISTRATION = "insurer-login";

	static final String CLIENT_ID = "insurer-audit";

	/** ログインサーバーの受け口のパス。 */
	private static final String OIDC = "/protocol/openid-connect";

	@Bean
	SecurityFilterChain auditChain(HttpSecurity http, ClientRegistrationRepository clients, AuditProperties props)
			throws Exception {
		// サインアウトでは、認可サーバーのログインも終わらせる（D-33）。残ると、次に開いたときに、前の人のまま通ってしまう
		OidcClientInitiatedLogoutSuccessHandler signedOut = new OidcClientInitiatedLogoutSuccessHandler(clients);
		signedOut.setPostLogoutRedirectUri(props.publicOrigin() + "/");
		http.authorizeHttpRequests((a) -> a.requestMatchers("/error").permitAll().anyRequest().hasRole("AUDITOR"))
			.oauth2Login((o) -> o.authorizationEndpoint((e) -> e.authorizationRequestResolver(pkce(clients)))
				.tokenEndpoint((t) -> t.accessTokenResponseClient(tokenClient(props)))
				.userInfoEndpoint((u) -> u.userAuthoritiesMapper(rolesFromIdToken())))
			.logout((l) -> l.logoutSuccessHandler(signedOut));
		return http.build();
	}

	@Bean
	ClientRegistrationRepository clientRegistrations(AuditProperties props) {
		// 公開名と内部の名前が違うので、発見の文書（.well-known）は使わず、受け口を 1 つずつ決める
		ClientRegistration registration = ClientRegistration.withRegistrationId(REGISTRATION)
			.clientId(CLIENT_ID)
			.clientAuthenticationMethod(new ClientAuthenticationMethod("federated-jwt"))
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(props.publicOrigin() + "/login/oauth2/code/" + REGISTRATION)
			.scope("openid")
			.issuerUri(props.issuer())
			.authorizationUri(props.issuer() + OIDC + "/auth")
			.tokenUri(props.loginUrl() + "/realms/insurer" + OIDC + "/token")
			.jwkSetUri(props.loginUrl() + "/realms/insurer" + OIDC + "/certs")
			.providerConfigurationMetadata(Map.of("end_session_endpoint", props.issuer() + OIDC + "/logout"))
			.userNameAttributeName("sub")
			.clientName("ログインサーバー")
			.build();
		return new InMemoryClientRegistrationRepository(registration);
	}

	/** confidential client でも、認可コードを PKCE で結ぶ。 */
	private static OAuth2AuthorizationRequestResolver pkce(ClientRegistrationRepository clients) {
		DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(clients,
				OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
		resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
		return resolver;
	}

	/**
	 * トークンの要求のクライアント認証には、JWT-SVID を示す（D-38）。秘密の値は持たない。
	 * 標準の部品は、この認証の方式を知らないと断るので、要求の組み立てを明示して、その確かめを外す。
	 */
	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenClient(AuditProperties props) {
		RestClientAuthorizationCodeTokenResponseClient client = new RestClientAuthorizationCodeTokenResponseClient();
		client.setParametersConverter(new DefaultOAuth2TokenRequestParametersConverter<>());
		client.setParametersCustomizer((parameters) -> {
			parameters.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe");
			parameters.set("client_assertion", jwtSvid(props));
		});
		return client;
	}

	private static String jwtSvid(AuditProperties props) {
		try {
			return Files.readString(Path.of(props.jwtSvidFile())).trim();
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	/** ID トークンの roles（ログインサーバーが載せる）を、役割にする。 */
	private static GrantedAuthoritiesMapper rolesFromIdToken() {
		return (Collection<? extends GrantedAuthority> authorities) -> {
			Set<GrantedAuthority> mapped = new HashSet<>(authorities);
			for (GrantedAuthority authority : authorities) {
				if (authority instanceof OidcUserAuthority oidc
						&& oidc.getIdToken().getClaim("roles") instanceof List<?> roles) {
					roles.forEach((role) -> mapped.add(new SimpleGrantedAuthority("ROLE_" + role)));
				}
			}
			return mapped;
		};
	}

}
