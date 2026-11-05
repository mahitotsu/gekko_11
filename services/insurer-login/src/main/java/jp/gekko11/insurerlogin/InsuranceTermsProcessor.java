package jp.gekko11.insurerlogin;

import java.util.List;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.protocol.oidc.rar.InvalidAuthorizationDetailsException;
import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;

/**
 * 取決めの範囲（RFC 9396 の authorization_details）の形を確かめる（D-39）。
 * 認可の要求とトークンの要求で呼ばれ、形が違えば断る。通った範囲は、製品が A に載せる。
 */
final class InsuranceTermsProcessor implements AuthorizationDetailsProcessor<AuthorizationDetailsJSONRepresentation> {

	static final String TYPE = "insurance_application";

	@Override
	public boolean isSupported() {
		return true;
	}

	@Override
	public String getSupportedType() {
		return TYPE;
	}

	@Override
	public Class<AuthorizationDetailsJSONRepresentation> getSupportedResponseJavaType() {
		return AuthorizationDetailsJSONRepresentation.class;
	}

	@Override
	public AuthorizationDetailsJSONRepresentation validateAuthorizationDetail(
			AuthorizationDetailsJSONRepresentation detail) throws InvalidAuthorizationDetailsException {
		if (!(detail.getCustomData().get("kinds") instanceof List<?>)
				|| !(detail.getCustomData().get("maxBenefit") instanceof Number)) {
			throw new InvalidAuthorizationDetailsException("kinds and maxBenefit are required");
		}
		return detail;
	}

	@Override
	public AuthorizationDetailsJSONRepresentation process(UserSessionModel user, ClientSessionContext client,
			AuthorizationDetailsJSONRepresentation detail) throws InvalidAuthorizationDetailsException {
		return validateAuthorizationDetail(detail);
	}

	@Override
	public List<AuthorizationDetailsJSONRepresentation> handleMissingAuthorizationDetails(UserSessionModel user,
			ClientSessionContext client) {
		return null;
	}

	@Override
	public AuthorizationDetailsJSONRepresentation processStoredAuthorizationDetails(UserSessionModel user,
			ClientSessionContext client, AuthorizationDetailsJSONRepresentation detail) {
		return detail;
	}

	@Override
	public void afterAuthorizationDetailsProcessed(UserSessionModel user, ClientSessionContext client,
			AuthorizationDetailsJSONRepresentation detail) {
	}

	@Override
	public void close() {
	}

}
