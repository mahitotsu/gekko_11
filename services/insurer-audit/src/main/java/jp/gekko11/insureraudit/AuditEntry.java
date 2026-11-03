package jp.gekko11.insureraudit;

import java.util.Map;

/**
 * Loki に届いた監査の記録 1 行。
 *
 * @param app 書いた Pod の印（Alloy が付ける。記録の中の service の欄ではない）
 * @param container 書いたコンテナー（同上）
 * @param at Loki が受け取った時刻（ナノ秒）
 * @param record 記録（"audit" の欄の中身）
 */
record AuditEntry(String app, String container, long at, Map<String, Object> record) {

	/** 記録の種類ごとに、書いてよい Pod とコンテナー（D-32）。 */
	private static final Map<String, String> WRITER = Map.of("issue", "insurer-auth", "exchange", "insurer-auth",
			"tool_call", "insurer-mcp", "contract", "insurer-backend", "conversation", "sales-agent");

	String kind() {
		return (String) this.record.get("kind");
	}

	Object get(String key) {
		return this.record.get(key);
	}

	/** 書いた者が、その種類の記録を書いてよい者か。認可サーバーはアプリだけのコンテナーで、ほかは Envoy などと並ぶ app のコンテナーである。 */
	boolean writtenByOwner() {
		String owner = WRITER.get(kind());
		if (owner == null || !owner.equals(this.app)) {
			return false;
		}
		return ("insurer-auth".equals(owner) ? "insurer-auth" : "app").equals(this.container);
	}

	/** その種類の記録を書いてよい者。 */
	String expectedWriter() {
		return WRITER.getOrDefault(kind(), "（決まっていない種類）");
	}

}
