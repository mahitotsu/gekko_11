package jp.gekko11.insurerauth;

import java.net.MalformedURLException;
import java.net.URI;
import java.security.Principal;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jwt.JWTParser;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

/**
 * ログインサーバーが出した A を確かめて、保存先に取り込む（D-36）。標準の交換の部品は、保存先にあるトークンしか替えない（F-G77）。
 * 取り込めば、後の確かめ（ExchangeGuard、標準の部品）と記録は、自分が出したトークンと同じように動く。
 * 教材のための意図的に悪い確かめを含む。vulnerable の名前空間では、D28 を外せる。本番の部品として使わないこと。
 */
final class ExternalSubjectImporter implements AuthenticationProvider {

	/** 取り込んだ A を出されたクライアント。この認可サーバーの登録ではなく、保存の形を満たすためにある。 */
	private static final RegisteredClient CUSTOMER_APP = RegisteredClient.withId(ExchangePolicy.CUSTOMER_APP)
		.clientId(ExchangePolicy.CUSTOMER_APP)
		.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
		.redirectUri("https://login.invalid/")
		.build();

	private static final MappedJwtClaimSetConverter CLAIMS = MappedJwtClaimSetConverter.withDefaults(Map.of());

	private final AuthenticationProvider delegate;

	private final OAuth2AuthorizationService authorizationService;

	private final JwtDecoder decoder;

	private final Defenses defenses;

	ExternalSubjectImporter(AuthenticationProvider delegate, OAuth2AuthorizationService authorizationService,
			JwtDecoder decoder, Defenses defenses) {
		this.delegate = delegate;
		this.authorizationService = authorizationService;
		this.decoder = decoder;
		this.defenses = defenses;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String subject = ((OAuth2TokenExchangeAuthenticationToken) authentication).getSubjectToken();
		if (this.authorizationService.findByToken(subject, OAuth2TokenType.ACCESS_TOKEN) == null) {
			this.authorizationService.save(imported(subject, verified(subject)));
		}
		return this.delegate.authenticate(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

	private Map<String, Object> verified(String token) {
		try {
			if (this.defenses.enabled(Defenses.VERIFY_SUBJECT)) {
				return this.decoder.decode(token).getClaims();
			}
			// 悪い確かめ（D28 を外す）: 署名も発行者も見ず、中身を読むだけ
			return CLAIMS.convert(JWTParser.parse(token).getJWTClaimsSet().getClaims());
		}
		catch (JwtException | ParseException ex) {
			throw reject("subject_token could not be verified");
		}
	}

	private static OAuth2Authorization imported(String token, Map<String, Object> verified) {
		if (!ExchangePolicy.CUSTOMER_APP.equals(verified.get("azp")) || !(verified.get("sub") instanceof String sub)
				|| !(verified.get("may_act") instanceof Map<?, ?> mayAct)) {
			throw reject("subject_token is not a token A");
		}
		Map<String, Object> claims = new HashMap<>(verified);
		claims.put("may_act", withUrlIssuer(mayAct));
		Set<String> scopes = (verified.get("scope") instanceof String scope)
				? Arrays.stream(scope.split(" ")).collect(Collectors.toSet()) : Set.of();
		OAuth2AccessToken access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.DPOP, token,
				(Instant) verified.get("iat"), (Instant) verified.get("exp"), scopes);
		Authentication principal = UsernamePasswordAuthenticationToken.authenticated(sub, null,
				AuthorityUtils.NO_AUTHORITIES);
		return OAuth2Authorization.withRegisteredClient(CUSTOMER_APP)
			.principalName(sub)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizedScopes(scopes)
			.attribute(Principal.class.getName(), principal)
			.token(access, (metadata) -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.build();
	}

	/** 標準の部品は、may_act の iss を、URL の型で保存した actor_token の iss と比べる（F-G51）。JWT では文字列なので、直す。 */
	private static Map<String, Object> withUrlIssuer(Map<?, ?> mayAct) {
		Map<String, Object> copy = new LinkedHashMap<>();
		mayAct.forEach((key, value) -> copy.put(String.valueOf(key), value));
		try {
			copy.put("iss", URI.create(String.valueOf(mayAct.get("iss"))).toURL());
		}
		catch (MalformedURLException | IllegalArgumentException ex) {
			throw reject("may_act has no valid iss");
		}
		return copy;
	}

	private static OAuth2AuthenticationException reject(String description) {
		return new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, description, null));
	}

}
