package jp.gekko11.insurerauth;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;

/**
 * 交換でトークンを出すたびに、監査のための記録を 1 行の JSON で書く（D-17、D-30）。Alloy が集め、名前空間の Loki に入れる。
 * 出したトークンの jti と、交換の元のトークンの jti で、A → B → C をたどれる。A の発行は、ログインサーバーが issue として書く。
 * トークンそのものは書かない。
 */
final class IssuanceRecorder implements AuthenticationProvider {

	private static final ObjectMapper JSON = new ObjectMapper();

	private final AuthenticationProvider delegate;

	private final OAuth2AuthorizationService authorizationService;

	IssuanceRecorder(AuthenticationProvider delegate, OAuth2AuthorizationService authorizationService) {
		this.delegate = delegate;
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = this.delegate.authenticate(authentication);
		if (result instanceof OAuth2AccessTokenAuthenticationToken issued) {
			Map<String, Object> claims = claimsOf(issued.getAccessToken().getTokenValue());
			if (claims != null) {
				Map<String, Object> record = new LinkedHashMap<>();
				record.put("kind", "exchange");
				record.put("at", Instant.now().getEpochSecond());
				record.put("service", "insurer-auth");
				record.put("client", issued.getRegisteredClient().getClientId());
				record.put("sub", claims.get("sub"));
				record.put("aud", claims.get("aud"));
				record.put("jti", claims.get("jti"));
				record.put("act", claims.get("act"));
				Map<String, Object> from = claimsOf(((OAuth2TokenExchangeAuthenticationToken) authentication).getSubjectToken());
				record.put("from_jti", (from == null) ? null : from.get("jti"));
				write(record);
			}
		}
		return result;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

	private Map<String, Object> claimsOf(String token) {
		OAuth2Authorization authorization = this.authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
		OAuth2Authorization.Token<?> found = (authorization == null) ? null : authorization.getToken(token);
		return (found == null) ? null : found.getClaims();
	}

	static void write(Map<String, Object> record) {
		try {
			System.out.println(JSON.writeValueAsString(Map.of("audit", record)));
		}
		catch (Exception ex) {
			System.out.println("{\"audit_error\":\"記録を書けない\"}");
		}
	}

}
