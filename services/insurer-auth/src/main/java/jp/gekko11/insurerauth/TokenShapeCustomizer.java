package jp.gekko11.insurerauth;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * トークンの形を整える。cnf と act は、標準の customizer が先に書く（F-G49）。ここでは次を書く。
 * <ul>
 * <li>typ を at+jwt にする（RFC 9068）</li>
 * <li>aud を、トークンを受け取るサービスにする（A は営業 AI エージェント、交換では求めた宛先）</li>
 * <li>受け取るサービスが替える窓口なら、may_act にそのサービスを入れる（D-7 の手順 3）</li>
 * <li>取決めの範囲（authorization_details）と、確認済みの属性（verified_claims）を載せ、交換では引き継ぐ</li>
 * </ul>
 * 顧客のアプリのトークンは、DPoP の proof がなければ出さない（D-18）。
 * 教材のための意図的に悪い発行を含む。vulnerable の名前空間では、D3a〜D3e を外せる。本番の部品として使わないこと。
 */
final class TokenShapeCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private static final String TERMS = "authorization_details";

	private static final String VERIFIED = "verified_claims";

	private static final ObjectMapper JSON = new ObjectMapper();

	private final Defenses defenses;

	private final UserDirectory users;

	TokenShapeCustomizer(Defenses defenses, UserDirectory users) {
		this.defenses = defenses;
		this.users = users;
	}

	@Override
	public void customize(JwtEncodingContext context) {
		if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			// 悪い発行（D3c を外す）: ID トークンの宛先に、API の識別子まで入れる
			if (!this.defenses.enabled(Defenses.ID_TOKEN_AUD)) {
				List<String> aud = new ArrayList<>(List.of(context.getRegisteredClient().getClientId()));
				aud.addAll(ExchangePolicy.SERVICES);
				context.getClaims().audience(aud);
			}
			return;
		}
		if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
			return;
		}
		context.getJwsHeader().type("at+jwt");
		AuthorizationGrantType grant = context.getAuthorizationGrantType();
		String client = context.getRegisteredClient().getClientId();

		String audience = null;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grant) && ExchangePolicy.CUSTOMER_APP.equals(client)) {
			if (context.get(OAuth2TokenContext.DPOP_PROOF_KEY) == null) {
				throw new OAuth2AuthenticationException(
						new OAuth2Error("invalid_dpop_proof", "DPoP proof is required", null));
			}
			audience = ExchangePolicy.CUSTOMER_AUDIENCE;
			customerClaims(context);
		}
		else if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(grant)
				&& context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken exchange) {
			Set<String> audiences = exchange.getAudiences();
			audience = (audiences.size() == 1) ? audiences.iterator().next() : null;
			inheritedClaims(context, exchange);
		}
		else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(grant)) {
			audience = ExchangePolicy.next(client);
		}

		if (audience != null) {
			// 悪い発行（D3a を外す）: どの窓口でも通る、全ての宛先のトークン
			context.getClaims()
				.audience(this.defenses.enabled(Defenses.AUD_ONE) ? List.of(audience) : ExchangePolicy.SERVICES);
			if (ExchangePolicy.exchanges(audience)) {
				context.getClaims().claim("may_act", Map.of("iss", issuer(context), "sub", audience));
			}
		}
		// 悪い発行（D3b を外す）: 長い有効期間
		if (!this.defenses.enabled(Defenses.SHORT_TTL)) {
			context.getClaims().expiresAt(java.time.Instant.now().plus(Duration.ofHours(24)));
		}
		// 悪い発行（D3d を外す）: 替えるときに、経由（act）を落とす
		if (!this.defenses.enabled(Defenses.KEEP_ACT)) {
			context.getClaims().claims((claims) -> claims.remove("act"));
		}
	}

	/** A に、顧客が同意した取決めの範囲と、確認済みの属性を載せる。 */
	private void customerClaims(JwtEncodingContext context) {
		OAuth2Authorization authorization = context.getAuthorization();
		OAuth2AuthorizationRequest request = (authorization != null)
				? authorization.getAttribute(OAuth2AuthorizationRequest.class.getName()) : null;
		Object requested = (request != null) ? request.getAdditionalParameters().get(TERMS) : null;
		if (requested instanceof String raw) {
			context.getClaims().claim(TERMS, parseTerms(raw));
		}
		this.users.verifiedClaims(context.getPrincipal().getName())
			.ifPresent((v) -> context.getClaims().claim(VERIFIED, v));
	}

	/** 交換では、出されたトークンの取決めと確認済みの属性を引き継ぐ。取決めは、狭めるだけにする（D3e）。 */
	private void inheritedClaims(JwtEncodingContext context, OAuth2TokenExchangeAuthenticationToken exchange) {
		OAuth2Authorization subject = context.getAuthorization();
		OAuth2Authorization.Token<?> token = (subject != null) ? subject.getToken(exchange.getSubjectToken()) : null;
		Map<String, Object> claims = (token != null && token.getClaims() != null) ? token.getClaims() : Map.of();
		if (claims.get(VERIFIED) != null) {
			context.getClaims().claim(VERIFIED, claims.get(VERIFIED));
		}
		List<Map<String, Object>> original = asTerms(claims.get(TERMS));
		Object requested = exchange.getAdditionalParameters().get(TERMS);
		List<Map<String, Object>> terms = original;
		if (requested instanceof String raw) {
			List<Map<String, Object>> wanted = parseTerms(raw);
			// 悪い発行（D3e を外す）: 求められたとおりに広げる
			terms = this.defenses.enabled(Defenses.NARROW_TERMS) ? narrow(original, wanted) : wanted;
		}
		if (terms != null) {
			context.getClaims().claim(TERMS, terms);
		}
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> asTerms(Object value) {
		return (value instanceof List<?> list) ? (List<Map<String, Object>>) list : null;
	}

	private static List<Map<String, Object>> parseTerms(String raw) {
		try {
			return JSON.readValue(raw, new TypeReference<>() {
			});
		}
		catch (Exception ex) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_authorization_details", raw, null));
		}
	}

	/** 種類は共通部分、上限は小さいほう。元がなければ、何も許さない。 */
	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> narrow(List<Map<String, Object>> original,
			List<Map<String, Object>> wanted) {
		if (original == null || original.isEmpty() || wanted.isEmpty()) {
			return original;
		}
		Map<String, Object> o = original.get(0);
		Map<String, Object> w = wanted.get(0);
		List<Object> kinds = new ArrayList<>((List<Object>) w.getOrDefault("kinds", List.of()));
		kinds.retainAll((List<Object>) o.getOrDefault("kinds", List.of()));
		long max = Math.min(((Number) o.getOrDefault("maxBenefit", 0)).longValue(),
				((Number) w.getOrDefault("maxBenefit", 0)).longValue());
		Map<String, Object> narrowed = new LinkedHashMap<>(o);
		narrowed.put("kinds", kinds);
		narrowed.put("maxBenefit", max);
		return List.of(narrowed);
	}

	/**
	 * 標準の交換の部品は、may_act の iss を、保存した actor_token の iss と Objects.equals で比べる。
	 * 保存した iss は URL の型になるので、may_act の iss も URL の型で入れる。JWT では文字列になる（F-G51）。
	 */
	private static URL issuer(JwtEncodingContext context) {
		try {
			return URI.create(context.getAuthorizationServerContext().getIssuer()).toURL();
		}
		catch (MalformedURLException ex) {
			throw new IllegalStateException(ex);
		}
	}

}
