package jp.gekko11.insurerlogin;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessorFactory;
import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;
import org.keycloak.util.AuthorizationDetailsParser;

/** 製品は、type の値と同じ ID の部品を探す。応答の組み立てには、type ごとの変換の部品も要る（F-G78）。 */
public final class InsuranceTermsProcessorFactory implements AuthorizationDetailsProcessorFactory {

	@Override
	public AuthorizationDetailsProcessor<?> create(KeycloakSession session) {
		return new InsuranceTermsProcessor();
	}

	@Override
	public void init(Config.Scope config) {
		AuthorizationDetailsParser.registerParser(InsuranceTermsProcessor.TYPE, new AuthorizationDetailsParser() {
			@Override
			public <T extends AuthorizationDetailsJSONRepresentation> T asSubtype(
					AuthorizationDetailsJSONRepresentation detail, Class<T> type) {
				return type.cast(detail);
			}
		});
	}

	@Override
	public String getId() {
		return InsuranceTermsProcessor.TYPE;
	}

}
