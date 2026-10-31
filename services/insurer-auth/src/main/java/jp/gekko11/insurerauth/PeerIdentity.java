package jp.gekko11.insurerauth;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

/** TLS で示された相手の証明書から、SPIFFE ID を読む。連鎖は、TLS の層が SPIRE の bundle で確かめ済みである。 */
final class PeerIdentity {

	private PeerIdentity() {
	}

	static Optional<String> spiffeId(HttpServletRequest request) {
		X509Certificate[] chain = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
		if (chain == null || chain.length == 0) {
			return Optional.empty();
		}
		List<String> uris = SpiffeCertificateVerifier.uriNames(chain[0]);
		return (uris.size() == 1) ? Optional.of(uris.get(0)) : Optional.empty();
	}

	static boolean is(HttpServletRequest request, String expected) {
		return spiffeId(request).filter(expected::equals).isPresent();
	}

}
