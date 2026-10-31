package jp.gekko11.insurerauth;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;

/**
 * 交換の前に、標準の部品が確かめないことを確かめてから、標準の部品に渡す（D-7 の手順 2〜4）。
 * <ul>
 * <li>出されたトークンの宛先が、替えを頼む者自身であること</li>
 * <li>求める宛先が、その窓口が替えてよい宛先であること</li>
 * <li>actor_token が、替えを頼む者自身のもので、いま示した証明書に結ばれていること</li>
 * </ul>
 * may_act と actor_token の照合、結び直し、act の入れ子は、標準の部品が行う。
 */
final class ExchangeGuard implements AuthenticationProvider {

	private final AuthenticationProvider delegate;

	private final OAuth2AuthorizationService authorizationService;

	ExchangeGuard(AuthenticationProvider delegate, OAuth2AuthorizationService authorizationService) {
		this.delegate = delegate;
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenExchangeAuthenticationToken exchange = (OAuth2TokenExchangeAuthenticationToken) authentication;
		if (!(exchange.getPrincipal() instanceof OAuth2ClientAuthenticationToken client) || !client.isAuthenticated()
				|| !(client.getCredentials() instanceof X509Certificate[] chain)) {
			throw reject(OAuth2ErrorCodes.INVALID_CLIENT, "exchange requires tls_client_auth");
		}
		String requester = client.getRegisteredClient().getClientId();

		Map<String, Object> subject = claimsOf(exchange.getSubjectToken());
		if (subject == null || !audiences(subject).contains(requester)) {
			throw reject(OAuth2ErrorCodes.INVALID_GRANT, "subject_token is not addressed to the requester");
		}

		Set<String> audiences = exchange.getAudiences();
		if (audiences.size() != 1 || !ExchangePolicy.mayExchangeTo(requester, audiences.iterator().next())) {
			throw reject("invalid_target", "audience is not allowed for the requester");
		}

		Map<String, Object> actor = claimsOf(exchange.getActorToken());
		if (actor == null || !requester.equals(actor.get("sub"))
				|| !thumbprint(chain[0]).equals(x5t(actor))) {
			throw reject(OAuth2ErrorCodes.INVALID_GRANT, "actor_token is not bound to the requester certificate");
		}
		return this.delegate.authenticate(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

	private Map<String, Object> claimsOf(String token) {
		if (token == null) {
			return null;
		}
		OAuth2Authorization authorization = this.authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			return null;
		}
		OAuth2Authorization.Token<?> found = authorization.getToken(token);
		return (found == null || !found.isActive()) ? null : found.getClaims();
	}

	private static Collection<?> audiences(Map<String, Object> claims) {
		Object aud = claims.get("aud");
		return (aud instanceof Collection<?> c) ? c : (aud == null) ? List.of() : List.of(aud);
	}

	private static Object x5t(Map<String, Object> claims) {
		return (claims.get("cnf") instanceof Map<?, ?> cnf) ? cnf.get("x5t#S256") : null;
	}

	static String thumbprint(X509Certificate certificate) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}
		catch (Exception ex) {
			throw reject(OAuth2ErrorCodes.SERVER_ERROR, "thumbprint");
		}
	}

	private static OAuth2AuthenticationException reject(String code, String description) {
		return new OAuth2AuthenticationException(new OAuth2Error(code, description, null));
	}

}
