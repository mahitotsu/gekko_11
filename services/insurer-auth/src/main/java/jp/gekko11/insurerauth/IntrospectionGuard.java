package jp.gekko11.insurerauth;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;

/**
 * 有効性の問い合わせで、取り次いだ窓口（act の連鎖）と、トークンを受け取ったクライアントが、
 * 全て登録されていて外れていないことを確かめる（D10、P-13）。外れていれば、有効でないと答える。
 */
final class IntrospectionGuard implements AuthenticationProvider {

	private final AuthenticationProvider delegate;

	private final ClientRevocation revocation;

	IntrospectionGuard(AuthenticationProvider delegate, ClientRevocation revocation) {
		this.delegate = delegate;
		this.revocation = revocation;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenIntrospectionAuthenticationToken result = (OAuth2TokenIntrospectionAuthenticationToken) this.delegate
			.authenticate(authentication);
		OAuth2TokenIntrospection claims = result.getTokenClaims();
		if (!claims.isActive() || chain(claims.getClaims()).stream().noneMatch(this.revocation::isRevoked)) {
			return result;
		}
		return new OAuth2TokenIntrospectionAuthenticationToken(result.getToken(),
				(Authentication) result.getPrincipal(), OAuth2TokenIntrospection.builder().build());
	}

	private static List<String> chain(Map<String, Object> claims) {
		List<String> ids = new ArrayList<>();
		Object act = claims.get("act");
		while (act instanceof Map<?, ?> a) {
			ids.add(String.valueOf(a.get("sub")));
			act = a.get("act");
		}
		if (claims.get("client_id") != null) {
			ids.add(String.valueOf(claims.get("client_id")));
		}
		return ids;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

}
