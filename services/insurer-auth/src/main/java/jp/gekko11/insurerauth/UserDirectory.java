package jp.gekko11.insurerauth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Component;

/** 顧客と、取引時確認（本人確認）の記録。記録のない顧客は、本人確認が済んでいない（D11）。 */
@Component
class UserDirectory {

	record Verification(String method, String time) {
	}

	record Customer(String name, Verification verification) {
	}

	private final Map<String, Customer> customers = Map.of(
			"alice", new Customer("Alice", new Verification("対面で本人確認書類を確認", "2026-01-15")),
			"bob", new Customer("Bob", new Verification("対面で本人確認書類を確認", "2026-01-15")),
			"mallory", new Customer("Mallory", null));

	java.util.Set<String> names() {
		return this.customers.keySet();
	}

	/** OpenID Connect for Identity Assurance の最小の形（P-9）。 */
	Optional<Map<String, Object>> verifiedClaims(String user) {
		Customer c = this.customers.get(user);
		if (c == null || c.verification() == null) {
			return Optional.empty();
		}
		Map<String, Object> verification = new LinkedHashMap<>();
		verification.put("trust_framework", "jp_aml");
		verification.put("method", c.verification().method());
		verification.put("time", c.verification().time());
		return Optional.of(Map.of("verification", verification, "claims", Map.of("name", c.name())));
	}

}
