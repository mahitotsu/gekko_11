package jp.gekko11.insurerauth;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationContext;

/**
 * tls_client_auth で、証明書の SAN の URI（SPIFFE ID）を、登録した SPIFFE ID と照らす（D-16）。
 * 既定の照合は Subject DN を見るので、差し替える。証明書の連鎖は、TLS の層が SPIRE の bundle で確かめる。
 * 登録を外した窓口は、ここで拒む。
 */
final class SpiffeCertificateVerifier implements Consumer<OAuth2ClientAuthenticationContext> {

	static final String SPIFFE_ID = "spiffe_id";

	private static final int URI_NAME = 6;

	private final ClientRevocation revocation;

	SpiffeCertificateVerifier(ClientRevocation revocation) {
		this.revocation = revocation;
	}

	@Override
	public void accept(OAuth2ClientAuthenticationContext context) {
		X509Certificate[] chain = (X509Certificate[]) context.getAuthentication().getCredentials();
		String expected = context.getRegisteredClient().getClientSettings().getSetting(SPIFFE_ID);
		List<String> uris = uriNames(chain[0]);
		if (expected == null || uris.size() != 1 || !expected.equals(uris.get(0))) {
			throw new OAuth2AuthenticationException(
					new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client authentication failed: spiffe_id", null));
		}
		// 登録を外した窓口には、新しいトークンを出さない（G4）
		if (this.revocation.isRevoked(context.getRegisteredClient().getClientId())) {
			throw new OAuth2AuthenticationException(
					new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client registration is revoked", null));
		}
	}

	static List<String> uriNames(X509Certificate certificate) {
		try {
			Collection<List<?>> names = certificate.getSubjectAlternativeNames();
			if (names == null) {
				return List.of();
			}
			return names.stream().filter((n) -> (Integer) n.get(0) == URI_NAME).map((n) -> (String) n.get(1)).toList();
		}
		catch (CertificateParsingException ex) {
			return List.of();
		}
	}

}
