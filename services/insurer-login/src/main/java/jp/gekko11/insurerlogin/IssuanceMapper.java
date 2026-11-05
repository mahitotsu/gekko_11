package jp.gekko11.insurerlogin;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;

/**
 * A を出すたびに、監査のための記録を 1 行の JSON で書く（D-17、D-30）。Alloy が集め、名前空間の Loki に入れる。
 * スコープ apply にだけ付けるので、A のほかのトークン（passkey の登録に使う P）では動かない。トークンそのものは書かない。
 * 教材のための意図的に悪い発行を含む。vulnerable の名前空間では、D3a〜D3c を外せる。本番の部品として使わないこと。
 */
public final class IssuanceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

	/** 悪い発行で入れる、全ての宛先（Spring の認可サーバーの ExchangePolicy.SERVICES と同じ）。 */
	private static final String[] SERVICES = { "sales-agent", "insurer-mcp", "insurer-backend" };

	@Override
	public String getId() {
		return "insurer-issuance-mapper";
	}

	@Override
	public String getDisplayType() {
		return "Insurer issuance";
	}

	@Override
	public String getDisplayCategory() {
		return TOKEN_MAPPER_CATEGORY;
	}

	@Override
	public String getHelpText() {
		return "Records the issuance of the token A for the audit.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of();
	}

	/** 宛先のマッパーの後に動く。 */
	@Override
	public int getPriority() {
		return 1000;
	}

	@Override
	public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mapping, KeycloakSession session,
			UserSessionModel user, ClientSessionContext client) {
		// 悪い発行（D3a を外す）: どの窓口でも通る、全ての宛先のトークン
		if (!Defenses.enabled(Defenses.AUD_ONE)) {
			token.audience(SERVICES);
		}
		// 悪い発行（D3b を外す）: 長い有効期間
		if (!Defenses.enabled(Defenses.SHORT_TTL)) {
			token.exp(Instant.now().plusSeconds(24 * 60 * 60).getEpochSecond());
		}
		Map<String, Object> record = new LinkedHashMap<>();
		record.put("kind", "issue");
		record.put("at", Instant.now().getEpochSecond());
		record.put("service", "insurer-login");
		record.put("client", client.getClientSession().getClient().getClientId());
		record.put("sub", token.getSubject());
		record.put("aud", token.getAudience());
		record.put("jti", token.getId());
		write(record);
		return token;
	}

	@Override
	public IDToken transformIDToken(IDToken token, ProtocolMapperModel mapping, KeycloakSession session,
			UserSessionModel user, ClientSessionContext client) {
		// 悪い発行（D3c を外す）: ID トークンの宛先に、API の識別子まで入れる
		if (!Defenses.enabled(Defenses.ID_TOKEN_AUD)) {
			String[] audience = new String[SERVICES.length + 1];
			audience[0] = client.getClientSession().getClient().getClientId();
			System.arraycopy(SERVICES, 0, audience, 1, SERVICES.length);
			token.audience(audience);
		}
		return token;
	}

	private static void write(Map<String, Object> record) {
		try {
			System.out.println(JsonSerialization.writeValueAsString(Map.of("audit", record)));
		}
		catch (Exception ex) {
			System.out.println("{\"audit_error\":\"記録を書けない\"}");
		}
	}

}
