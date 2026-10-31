package jp.gekko11.insurerbackend;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;

/** JCS（RFC 8785）で正規化し、ハッシュを取る。顧客のアプリが署名した内容と、同じ規則で比べる（D-1）。 */
final class Canonical {

	private static final ObjectMapper JSON = new ObjectMapper();

	private Canonical() {
	}

	static String of(Object value) {
		try {
			return new JsonCanonicalizer(JSON.writeValueAsString(value)).getEncodedString();
		}
		catch (Exception ex) {
			throw new IllegalArgumentException("正規化できない", ex);
		}
	}

	/** passkey に署名させる challenge。内容の正規化の SHA-256 で、内容が 1 文字でも変われば変わる。 */
	static byte[] digest(Object value) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(of(value).getBytes(StandardCharsets.UTF_8));
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	static String challengeOf(Object value) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest(value));
	}

}
