package jp.gekko11.insurerauth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationProvider;
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
	SecurityFilterChain authorizationServerChain(HttpSecurity http, OAuth2AuthorizationService authorizationService)
			throws Exception {
		OAuth2AuthorizationServerConfigurer server = OAuth2AuthorizationServerConfigurer.authorizationServer();
		http.securityMatcher(server.getEndpointsMatcher())
			.with(server, (s) -> s
				.clientAuthentication((c) -> c
					.authenticationConverters((converters) -> converters
						.replaceAll((v) -> (v instanceof X509ClientCertificateAuthenticationConverter)
								? new SpiffeCertificateConverter() : v))
					.authenticationProviders((providers) -> providers.forEach((p) -> {
						if (p instanceof X509ClientCertificateAuthenticationProvider x509) {
							x509.setCertificateVerifier(new SpiffeCertificateVerifier());
						}
					})))
				.tokenEndpoint((t) -> t.authenticationProviders((providers) -> providers
					.replaceAll((p) -> (p instanceof OAuth2TokenExchangeAuthenticationProvider)
							? new ExchangeGuard(p, authorizationService) : p))))
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
		http.authorizeHttpRequests((a) -> a.anyRequest().authenticated()).formLogin(Customizer.withDefaults());
		return http.build();
	}

	/** ログインは固定ユーザー（implementation の 5 章）。 */
	@Bean
	UserDetailsService users() {
		return new InMemoryUserDetailsManager(
				User.withUsername("alice").password("{noop}demo").roles("CUSTOMER").build(),
				User.withUsername("bob").password("{noop}demo").roles("CUSTOMER").build(),
				User.withUsername("mallory").password("{noop}demo").roles("CUSTOMER").build());
	}

	@Bean
	RegisteredClientRepository registeredClients(AuthProperties props) {
		RegisteredClient customerApp = RegisteredClient.withId(ExchangePolicy.CUSTOMER_APP)
			.clientId(ExchangePolicy.CUSTOMER_APP)
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(props.customerRedirectUri())
			.scope("apply")
			.clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
			.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(ACCESS_TOKEN_TTL).build())
			.build();
		return new InMemoryRegisteredClientRepository(customerApp, service(props, ExchangePolicy.SALES_AGENT),
				service(props, ExchangePolicy.INSURER_MCP));
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
	OAuth2TokenCustomizer<JwtEncodingContext> tokenShapeCustomizer() {
		return new TokenShapeCustomizer();
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
