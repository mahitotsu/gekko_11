package jp.gekko11.insurerauth;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * アクセストークンの形を整える。cnf と act は、標準の customizer が先に書く。ここでは次を書く。
 * <ul>
 * <li>typ を at+jwt にする（RFC 9068）</li>
 * <li>aud を、トークンを受け取るサービスにする（A は営業 AI エージェント、交換では求めた宛先）</li>
 * <li>受け取るサービスが替える窓口なら、may_act にそのサービスを入れる（D-7 の手順 3）</li>
 * </ul>
 * 顧客のアプリのトークンは、DPoP の proof がなければ出さない（D-18）。
 */
final class TokenShapeCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	@Override
	public void customize(JwtEncodingContext context) {
		if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
			return;
		}
		context.getJwsHeader().type("at+jwt");

		String audience = audience(context);
		if (audience == null) {
			return;
		}
		context.getClaims().audience(List.of(audience));
		if (ExchangePolicy.exchanges(audience)) {
			context.getClaims().claim("may_act", Map.of("iss", issuer(context), "sub", audience));
		}
	}

	/**
	 * 標準の交換の部品は、may_act の iss を、保存した actor_token の iss と Objects.equals で比べる。
	 * 保存した iss は URL の型になるので、may_act の iss も URL の型で入れる。JWT では文字列になる。
	 */
	private static URL issuer(JwtEncodingContext context) {
		try {
			return URI.create(context.getAuthorizationServerContext().getIssuer()).toURL();
		}
		catch (MalformedURLException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static String audience(JwtEncodingContext context) {
		AuthorizationGrantType grant = context.getAuthorizationGrantType();
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grant)
				&& ExchangePolicy.CUSTOMER_APP.equals(context.getRegisteredClient().getClientId())) {
			if (context.get(OAuth2TokenContext.DPOP_PROOF_KEY) == null) {
				throw new OAuth2AuthenticationException(new OAuth2Error("invalid_dpop_proof", "DPoP proof is required", null));
			}
			return ExchangePolicy.CUSTOMER_AUDIENCE;
		}
		if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(grant)
				&& context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken exchange) {
			Set<String> audiences = exchange.getAudiences();
			return audiences.size() == 1 ? audiences.iterator().next() : null;
		}
		return null;
	}

}
