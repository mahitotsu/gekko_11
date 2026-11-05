package jp.gekko11.insurerauth;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.web.authentication.X509ClientCertificateAuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

/** 認可サーバーの組み立て。拡張点は D-19 の表のとおり。 */
@Configuration
public class AuthorizationServerConfig {

	private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(5);

	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerChain(HttpSecurity http, OAuth2AuthorizationService authorizationService,
			Defenses defenses, ClientRevocation revocation, LoginKeys keys, AuthProperties props) throws Exception {
		OAuth2AuthorizationServerConfigurer server = OAuth2AuthorizationServerConfigurer.authorizationServer();
		http.securityMatcher(server.getEndpointsMatcher())
			.with(server, (s) -> s
				.clientAuthentication((c) -> c
					.authenticationConverters((converters) -> {
						// 証明書を示した要求は、1 枚の連鎖でも tls_client_auth として確かめる（F-G50）
						converters.removeIf((v) -> v instanceof X509ClientCertificateAuthenticationConverter);
						converters.add(0, new SpiffeCertificateConverter());
					})
					.authenticationProviders((providers) -> providers.forEach((p) -> {
						if (p instanceof X509ClientCertificateAuthenticationProvider x509) {
							x509.setCertificateVerifier(new SpiffeCertificateVerifier(revocation));
						}
					})))
				.tokenEndpoint((t) -> t.authenticationProviders((providers) -> providers.replaceAll((p) -> {
					// 交換は、ログインサーバーが出した A を取り込み（D-36）、前の確かめを通してから出す。交換で出したトークンは、監査のために記録する（D-17）
					if (p instanceof OAuth2TokenExchangeAuthenticationProvider) {
						return new IssuanceRecorder(new ExternalSubjectImporter(new ExchangeGuard(p, authorizationService, defenses),
								authorizationService, subjectDecoder(keys, props), defenses), authorizationService);
					}
					return p;
				})))
				.tokenIntrospectionEndpoint((i) -> i.authenticationProviders((providers) -> providers
					.replaceAll((p) -> (p instanceof OAuth2TokenIntrospectionAuthenticationProvider)
							? new IntrospectionGuard(p, revocation) : p))))
			.authorizeHttpRequests((a) -> a.anyRequest().authenticated())
			.exceptionHandling((e) -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain resourceChain(HttpSecurity http, LoginKeys keys, AuthProperties props) throws Exception {
		// 運用と内部の受け口は、相手の SPIFFE ID を各受け口で確かめる（AdminController、PasskeyController）。
		// passkey の受け口は、ログインサーバーが出した P を、DPoP の proof と一緒に確かめる（D-37）。proof のない Bearer は受けない
		http.authorizeHttpRequests((a) -> a.requestMatchers("/admin/**", "/internal/**")
			.permitAll()
			.anyRequest()
			.authenticated())
			.csrf((c) -> c.ignoringRequestMatchers("/admin/**", "/internal/**", "/passkeys/**"))
			.sessionManagement((m) -> m.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.oauth2ResourceServer((o) -> o.bearerTokenResolver((request) -> null)
				.jwt((j) -> j.decoder(passkeyDecoder(keys, props))));
		return http.build();
	}

	/** 交換に出された A を確かめる。宛先は、替えを頼む者と照らすので、ここでは見ない（ExchangeGuard）。 */
	private static JwtDecoder subjectDecoder(LoginKeys keys, AuthProperties props) {
		return loginDecoder(keys, props);
	}

	/** passkey の受け口に示された P を確かめる。宛先は、認可サーバー自身である。 */
	private static JwtDecoder passkeyDecoder(LoginKeys keys, AuthProperties props) {
		return loginDecoder(keys, props, new JwtClaimValidator<List<String>>("aud",
				(aud) -> aud != null && aud.contains(ExchangePolicy.INSURER_AUTH)));
	}

	/** ログインサーバーのトークンを、署名（RS256）、iss、typ、有効期間で確かめる。 */
	@SafeVarargs
	private static JwtDecoder loginDecoder(LoginKeys keys, AuthProperties props, OAuth2TokenValidator<Jwt>... more) {
		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys.source()));
		processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));
		processor.setJWTClaimsSetVerifier((claims, context) -> {
		});
		List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>(List.of(new JwtTimestampValidator(Duration.ZERO),
				new JwtIssuerValidator(props.loginIssuer())));
		validators.addAll(List.of(more));
		NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
		return decoder;
	}

	/** ログインサーバーの公開鍵。必要になってから、SPIFFE ID を確かめる出口を通して取る。 */
	@Bean
	LoginKeys loginKeys(AuthProperties props) throws Exception {
		return new LoginKeys(JWKSourceBuilder.<SecurityContext>create(URI.create(props.loginJwksUrl()).toURL()).build());
	}

	@Bean
	RegisteredClientRepository registeredClients(AuthProperties props) {
		// 保険会社のシステムは、有効性の問い合わせのために、クライアントとして認証する（D10）
		RegisteredClient backend = RegisteredClient.withId(ExchangePolicy.INSURER_BACKEND)
			.clientId(ExchangePolicy.INSURER_BACKEND)
			.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.clientSettings(ClientSettings.builder()
				.setting(SpiffeCertificateVerifier.SPIFFE_ID, props.spiffeId(ExchangePolicy.INSURER_BACKEND))
				.build())
			.build();
		return new InMemoryRegisteredClientRepository(service(props, ExchangePolicy.SALES_AGENT),
				service(props, ExchangePolicy.INSURER_MCP), backend);
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
	OAuth2TokenCustomizer<JwtEncodingContext> tokenShapeCustomizer(Defenses defenses) {
		return new TokenShapeCustomizer(defenses);
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
