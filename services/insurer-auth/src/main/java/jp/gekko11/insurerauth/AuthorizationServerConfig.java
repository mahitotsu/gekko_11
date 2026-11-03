package jp.gekko11.insurerauth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.X509ClientCertificateAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.web.authentication.X509ClientCertificateAuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/** 認可サーバーの組み立て。拡張点は D-19 の表のとおり。 */
@Configuration
public class AuthorizationServerConfig {

	private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(5);

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerChain(HttpSecurity http, OAuth2AuthorizationService authorizationService,
			Defenses defenses, ClientRevocation revocation) throws Exception {
		OAuth2AuthorizationServerConfigurer server = OAuth2AuthorizationServerConfigurer.authorizationServer();
		http.securityMatcher(server.getEndpointsMatcher())
			.with(server, (s) -> s
				.clientAuthentication((c) -> c
					.authenticationConverters((converters) -> {
						// 証明書を示した要求は、PKCE の値があっても、公開クライアントより先に tls_client_auth として確かめる
						// （監査サービスは、mTLS で認証し、PKCE も使う。D-31）。証明書のない顧客のアプリは、これまでどおり公開クライアントになる
						converters.removeIf((v) -> v instanceof X509ClientCertificateAuthenticationConverter);
						converters.add(0, new SpiffeCertificateConverter());
					})
					.authenticationProviders((providers) -> providers.forEach((p) -> {
						if (p instanceof X509ClientCertificateAuthenticationProvider x509) {
							x509.setCertificateVerifier(new SpiffeCertificateVerifier(revocation));
						}
					})))
				.tokenEndpoint((t) -> t.authenticationProviders((providers) -> providers.replaceAll((p) -> {
					// 交換は、前の確かめを通してから出す。ログインと交換で出したトークンは、監査のために記録する（D-17）
					if (p instanceof OAuth2TokenExchangeAuthenticationProvider) {
						return new IssuanceRecorder(new ExchangeGuard(p, authorizationService, defenses), authorizationService);
					}
					return (p instanceof OAuth2AuthorizationCodeAuthenticationProvider) ? new IssuanceRecorder(p, authorizationService) : p;
				})))
				.tokenIntrospectionEndpoint((i) -> i.authenticationProviders((providers) -> providers
					.replaceAll((p) -> (p instanceof OAuth2TokenIntrospectionAuthenticationProvider)
							? new IntrospectionGuard(p, revocation) : p)))
				.oidc(Customizer.withDefaults()))
			.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.exceptionHandling((e) -> e
				.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
						PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/token"))
				.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain loginChain(HttpSecurity http) throws Exception {
		// 運用と内部の受け口は、相手の SPIFFE ID を各受け口で確かめる（AdminController、PasskeyController）
		http.authorizeHttpRequests((a) -> a.requestMatchers("/admin/**", "/internal/**")
			.permitAll()
			.anyRequest()
			.authenticated())
			.csrf((c) -> c.ignoringRequestMatchers("/admin/**", "/internal/**", "/passkeys/**"))
			.formLogin(Customizer.withDefaults());
		return http.build();
	}

	/** ログインは固定ユーザー（implementation の 5 章）。顧客と、監査の担当（D-31）。 */
	@Bean
	UserDetailsService users(UserDirectory directory) {
		List<UserDetails> users = new ArrayList<>(directory.names()
			.stream()
			.map((name) -> User.withUsername(name).password("{noop}demo").roles("CUSTOMER").build())
			.toList());
		users.add(User.withUsername(UserDirectory.AUDITOR).password("{noop}demo").roles("AUDITOR").build());
		return new InMemoryUserDetailsManager(users);
	}

	@Bean
	RegisteredClientRepository registeredClients(AuthProperties props) {
		RegisteredClient customerApp = RegisteredClient.withId(ExchangePolicy.CUSTOMER_APP)
			.clientId(ExchangePolicy.CUSTOMER_APP)
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(props.customerRedirectUri())
			.scope("openid")
			.scope("apply")
			.clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
			.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(ACCESS_TOKEN_TTL).build())
			.build();
		// 保険会社のシステムは、有効性の問い合わせのために、クライアントとして認証する（D10）
		RegisteredClient backend = RegisteredClient.withId(ExchangePolicy.INSURER_BACKEND)
			.clientId(ExchangePolicy.INSURER_BACKEND)
			.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.clientSettings(ClientSettings.builder()
				.setting(SpiffeCertificateVerifier.SPIFFE_ID, props.spiffeId(ExchangePolicy.INSURER_BACKEND))
				.build())
			.build();
		// 監査サービスは、監査の担当のログインのために、OpenID Connect のクライアントとして、SVID の mTLS で認証する（D-31）
		RegisteredClient audit = RegisteredClient.withId(ExchangePolicy.INSURER_AUDIT)
			.clientId(ExchangePolicy.INSURER_AUDIT)
			.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(props.auditRedirectUri())
			.scope("openid")
			.clientSettings(ClientSettings.builder()
				.requireProofKey(true)
				.requireAuthorizationConsent(false)
				.setting(SpiffeCertificateVerifier.SPIFFE_ID, props.spiffeId(ExchangePolicy.INSURER_AUDIT))
				.build())
			.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(ACCESS_TOKEN_TTL).build())
			.build();
		return new InMemoryRegisteredClientRepository(customerApp, service(props, ExchangePolicy.SALES_AGENT),
				service(props, ExchangePolicy.INSURER_MCP), backend, audit);
	}

	/** 替えを頼む窓口。SPIFFE ID の mTLS で認証し、出すトークンをその証明書に結ぶ（D-7、D-16）。 */
	private static RegisteredClient service(AuthProperties props, String name) {
		return RegisteredClient.withId(name)
			.clientId(name)
			.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.scope("apply")
			.clientSettings(ClientSettings.builder()
				.setting(SpiffeCertificateVerifier.SPIFFE_ID, props.spiffeId(name))
				.build())
			.tokenSettings(TokenSettings.builder()
				.x509CertificateBoundAccessTokens(true)
				.accessTokenTimeToLive(ACCESS_TOKEN_TTL)
				.build())
			.build();
	}

	@Bean
	OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenShapeCustomizer(Defenses defenses, UserDirectory users) {
		return new TokenShapeCustomizer(defenses, users);
	}

	/** トークンの発行の鍵。起動ごとにメモリ上に作る（implementation の 5 章）。 */
	@Bean
	JWKSource<SecurityContext> jwkSource() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();
		RSAKey key = new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey((RSAPrivateKey) pair.getPrivate())
			.keyID(UUID.randomUUID().toString())
			.build();
		return new ImmutableJWKSet<>(new JWKSet(key));
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings(AuthProperties props) {
		return AuthorizationServerSettings.builder().issuer(props.issuer()).build();
	}

}
