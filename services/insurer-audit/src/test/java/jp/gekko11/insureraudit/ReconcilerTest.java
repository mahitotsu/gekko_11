package jp.gekko11.insureraudit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/** 突き合わせ。記録は、クラスタの各サービスが書く形を、メモリ上に置く。 */
class ReconcilerTest {

	private static final ObjectMapper JSON = new ObjectMapper();

	private static final String NONCE = "n-1";

	private static final Map<String, Object> FIXED_60 = Map.of("id", "fixed-60", "name", "確定年金 10年・年額60万円");

	private static final Map<String, Object> LIFE_240 = Map.of("id", "life-240", "name", "終身年金・年額240万円");

	private static final Map<String, Object> APPLICATION = Map.of("customer", "alice", "plan", FIXED_60, "nonce", NONCE);

	private static final Map<String, Object> ACT = Map.of("sub", "insurer-mcp", "act", Map.of("sub", "sales-agent"));

	/** メモリ上の記録。 */
	static final class Memory implements RecordSource {

		final List<AuditEntry> entries = new ArrayList<>();

		final List<Map<String, Object>> self = new ArrayList<>();

		private long at;

		Memory add(String app, String container, Map<String, Object> record) {
			this.entries.add(new AuditEntry(app, container, ++this.at, record));
			return this;
		}

		@Override
		public List<AuditEntry> search(String needle) {
			return this.entries.stream().filter((e) -> json(e.record()).contains(needle)).toList();
		}

		@Override
		public List<AuditEntry> contracts() {
			return this.entries.stream().filter((e) -> "contract".equals(e.kind())).toList();
		}

		@Override
		public List<Map<String, Object>> selfReported() {
			return this.self;
		}

	}

	private static String json(Object value) {
		try {
			return JSON.writeValueAsString(value);
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	private static Map<String, Object> rec(Object... kv) {
		Map<String, Object> m = new LinkedHashMap<>();
		for (int i = 0; i < kv.length; i += 2) {
			m.put((String) kv[i], kv[i + 1]);
		}
		return m;
	}

	/** 正規の申込み: ログインの A、営業 AI エージェントの B、事務サービスの C、ツールの記録、契約の記録、会話。 */
	static Memory regular(Map<String, Object> contractPlan, Object by, Object act) {
		String hash = Reconciler.hash(APPLICATION);
		Map<String, Object> contract = rec("contractId", "C-1", "customer", "alice", "plan", contractPlan, "nonce", NONCE);
		Memory m = new Memory();
		m.add("insurer-auth", "insurer-auth", rec("kind", "issue", "client", "customer-app", "sub", "alice", "jti", "jA"))
			.add("insurer-auth", "insurer-auth",
					rec("kind", "exchange", "client", "sales-agent", "sub", "alice", "jti", "jB", "from_jti", "jA", "act",
							Map.of("sub", "sales-agent")))
			.add("insurer-auth", "insurer-auth",
					rec("kind", "exchange", "client", "insurer-mcp", "sub", "alice", "jti", "jC", "from_jti", "jB", "act",
							act))
			.add("sales-agent", "app",
					rec("kind", "conversation", "thread", "t-1", "event", "agent_tool", "name", "get_offers", "nonce", NONCE))
			.add("sales-agent", "app", rec("kind", "conversation", "thread", "t-1", "event", "frontend_tool", "name",
					"present_application", "document_hash", hash))
			.add("insurer-mcp", "app",
					rec("kind", "tool_call", "tool", "submit_application", "sub", "alice", "jti", "jB", "nonce", NONCE,
							"customer", "alice", "plan", FIXED_60, "application_hash", hash, "contractId", "C-1",
							"status", 200))
			.add("insurer-backend", "app", rec("kind", "contract", "contract", contract, "by", by, "token_jti", "jC",
					"application_hash", hash));
		m.self.add(rec("contract", contract, "by", by, "application", APPLICATION, "tokenJti", "jC"));
		return m;
	}

	private static Map<String, Boolean> results(Reconciler.Report r) {
		Map<String, Boolean> out = new HashMap<>();
		r.checks().forEach((c) -> out.put(c.name().replaceAll("（.*", ""), c.ok()));
		return out;
	}

	@Test
	void regularContractHasNoMismatch() {
		Reconciler.Report r = new Reconciler(regular(FIXED_60, Reconciler.ROUTE, ACT)).reconcile(NONCE);
		assertThat(r.status()).as(r.checks().toString()).isEqualTo("食い違いなし");
		assertThat(r.chain()).extracting((c) -> c.get("jti")).containsExactly("jC", "jB", "jA");
		assertThat(r.conversation()).hasSize(2);
		assertThat(r.rejected()).isEmpty();
	}

	@Test
	void contractPlanDifferentFromSubmittedApplicationIsAMismatch() {
		// シナリオ 10: 保険会社のシステムが、申込みと違う案で契約を記録した
		Reconciler.Report r = new Reconciler(regular(LIFE_240, Reconciler.ROUTE, ACT)).reconcile(NONCE);
		assertThat(r.ok()).isFalse();
		assertThat(results(r)).containsEntry("申込みの中身", false).containsEntry("トークンの連鎖", true);
	}

	@Test
	void contractWithoutActIsARouteMismatch() {
		// シナリオ 20: 経由を残さない発行で、契約の記録に経由がない
		Reconciler.Report r = new Reconciler(regular(FIXED_60, List.of(), null)).reconcile(NONCE);
		assertThat(results(r)).containsEntry("経由", false).containsEntry("トークンの連鎖", true);
	}

	@Test
	void customerTokenSentStraightToTheBackendHasNoToolRecordAndNoChain() {
		// シナリオ 14: 営業 AI エージェント宛ての A で、保険会社のシステムへ直接申し込んだ
		Memory m = regular(FIXED_60, List.of(), null);
		m.entries.removeIf((e) -> "tool_call".equals(e.kind()) || "contract".equals(e.kind()));
		Map<String, Object> contract = rec("contractId", "C-1", "customer", "alice", "plan", FIXED_60, "nonce", NONCE);
		m.add("insurer-backend", "app", rec("kind", "contract", "contract", contract, "by", List.of(), "token_jti", "jA",
				"application_hash", Reconciler.hash(APPLICATION)));
		m.self.set(0, rec("contract", contract, "by", List.of(), "application", APPLICATION, "tokenJti", "jA"));
		Reconciler.Report r = new Reconciler(m).reconcile(NONCE);
		assertThat(results(r)).containsEntry("事務サービスの記録", false).containsEntry("トークンの連鎖", false);
	}

	@Test
	void recordWrittenByAnotherPodIsNotAccepted() {
		// 乗っ取られた営業 AI エージェントが、認可サーバーを名乗って、C の交換の記録を偽って書く
		Memory m = regular(FIXED_60, Reconciler.ROUTE, ACT);
		m.add("sales-agent", "app", rec("kind", "exchange", "service", "insurer-auth", "client", "insurer-mcp", "sub",
				"alice", "jti", "jC", "from_jti", "jX", "act", Map.of("sub", "insurer-mcp")));
		Reconciler.Report r = new Reconciler(m).reconcile(NONCE);
		assertThat(results(r)).containsEntry("トークンの連鎖", true).containsEntry("書いた者", false);
		assertThat(r.rejected()).singleElement().satisfies((x) -> assertThat(x.get("app")).isEqualTo("sales-agent"));
		assertThat(r.chain()).extracting((c) -> c.get("from_jti")).startsWith("jB");
	}

	@Test
	void conversationIsOnlyComparedAndMayBeMissing() {
		Memory m = regular(FIXED_60, Reconciler.ROUTE, ACT);
		m.entries.removeIf((e) -> "conversation".equals(e.kind()));
		assertThat(new Reconciler(m).reconcile(NONCE).ok()).isTrue();

		Memory shown = regular(FIXED_60, Reconciler.ROUTE, ACT);
		shown.add("sales-agent", "app", rec("kind", "conversation", "thread", "t-1", "event", "frontend_tool", "name",
				"present_application", "document_hash", "other"));
		assertThat(results(new Reconciler(shown).reconcile(NONCE))).containsEntry("会話", false);
	}

	@Test
	void selfReportDifferentFromLoggedContractIsAMismatch() {
		Memory m = regular(FIXED_60, Reconciler.ROUTE, ACT);
		Map<String, Object> changed = new LinkedHashMap<>(m.self.get(0));
		changed.put("contract", rec("contractId", "C-1", "customer", "alice", "plan", LIFE_240, "nonce", NONCE));
		m.self.set(0, changed);
		assertThat(results(new Reconciler(m).reconcile(NONCE))).containsEntry("自己申告と、契約の記録", false);
	}

}
