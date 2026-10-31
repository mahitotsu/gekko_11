package jp.gekko11.insurerbackend;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * token-guard が確かめた主張（x-auth-claims）。アプリは、トークンも証明書も持たず、この主張だけを使う（2-2）。
 *
 * @param claims トークンの主張
 * @param peer 相手の SPIFFE ID（mTLS で受けたとき）
 */
record Claims(Map<String, Object> claims, String peer) {

	private static final ObjectMapper JSON = new ObjectMapper();

	@SuppressWarnings("unchecked")
	static Claims from(String header) {
		if (header == null || header.isBlank()) {
			throw new IllegalArgumentException("確かめた主張がない");
		}
		try {
			Map<String, Object> summary = JSON.readValue(Base64.getUrlDecoder().decode(header), Map.class);
			Map<String, Object> peer = (Map<String, Object>) summary.getOrDefault("peer", Map.of());
			return new Claims((Map<String, Object>) summary.get("claims"), (String) peer.get("spiffeId"));
		}
		catch (java.io.IOException ex) {
			throw new IllegalArgumentException("確かめた主張が読めない", ex);
		}
	}

	String sub() {
		return (String) this.claims.get("sub");
	}

	/** 取り次いだ窓口。外側（最後に替えた者）から順に並べる。 */
	List<String> actChain() {
		List<String> chain = new ArrayList<>();
		Object act = this.claims.get("act");
		while (act instanceof Map<?, ?> a) {
			chain.add(String.valueOf(a.get("sub")));
			act = a.get("act");
		}
		return chain;
	}

	@SuppressWarnings("unchecked")
	Map<String, Object> verifiedClaims() {
		return (Map<String, Object>) this.claims.get("verified_claims");
	}

	@SuppressWarnings("unchecked")
	Map<String, Object> terms() {
		Object terms = this.claims.get("authorization_details");
		return (terms instanceof List<?> list && !list.isEmpty()) ? (Map<String, Object>) list.get(0) : null;
	}

	boolean hasScope(String scope) {
		Object s = this.claims.get("scope");
		if (s instanceof List<?> list) {
			return list.contains(scope);
		}
		return s instanceof String str && List.of(str.split(" ")).contains(scope);
	}

}
