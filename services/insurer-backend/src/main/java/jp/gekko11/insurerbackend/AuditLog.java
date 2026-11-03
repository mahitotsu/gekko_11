package jp.gekko11.insurerbackend;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 監査のための記録を、1 行の JSON で書く（D-17、D-30）。Alloy が集め、名前空間の Loki に入れる。
 * 一度書いた記録は、保険会社のシステムからは書き換えられない。監査サービスは、これと自己申告（/audit/records）を比べる。
 */
final class AuditLog {

	private static final ObjectMapper JSON = new ObjectMapper();

	private AuditLog() {
	}

	/** 契約を記録した。署名済み申込みはハッシュだけを書き、署名の値は書かない。 */
	static void contract(Map<String, Object> contract, List<String> by, String tokenJti, String applicationHash, long at) {
		Map<String, Object> record = new LinkedHashMap<>();
		record.put("kind", "contract");
		record.put("at", at);
		record.put("service", "insurer-backend");
		record.put("contract", contract);
		record.put("by", by);
		record.put("token_jti", tokenJti);
		record.put("application_hash", applicationHash);
		try {
			System.out.println(JSON.writeValueAsString(Map.of("audit", record)));
		}
		catch (Exception ex) {
			System.out.println("{\"audit_error\":\"記録を書けない\"}");
		}
	}

}
