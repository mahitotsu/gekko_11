package jp.gekko11.insurerauth;

import java.security.cert.X509Certificate;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * TLS で示された証明書を、tls_client_auth の認証として受け取る。
 * 標準の変換部品は、連鎖が 1 枚だと self_signed_tls_client_auth とみなす。SPIRE の SVID は、認証局の証明書を
 * 付けずに 1 枚で示されることが多いので、差し替える。連鎖は、TLS の層が SPIRE の bundle で確かめ済みである。
 */
final class SpiffeCertificateConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		X509Certificate[] chain = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
		if (chain == null || chain.length == 0 || request.getQueryString() != null
				&& request.getQueryString().contains(OAuth2ParameterNames.CLIENT_ID)) {
			return null;
		}
		String[] clientIds = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
		if (clientIds == null || !StringUtils.hasText(clientIds[0])) {
			return null;
		}
		if (clientIds.length != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		return new OAuth2ClientAuthenticationToken(clientIds[0], ClientAuthenticationMethod.TLS_CLIENT_AUTH, chain,
				Map.of());
	}

}
