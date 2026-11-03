package jp.gekko11.insureraudit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;

import org.springframework.stereotype.Component;

/**
 * 契約ごとに、保険会社のシステムの記録（自己申告）を、第三者の記録（認可サーバーの交換の記録、事務サービスのツールの記録）と
 * 突き合わせ、食い違いを示す（D-17、D25）。
 * <ul>
 * <li>書いた者は、記録の中の欄ではなく、Alloy が付ける Pod の印で決める。合わない記録は受け付けず、食い違いとして示す（D-32）</li>
 * <li>申込みの中身の根拠は、事務サービスが算出したハッシュである。会話の記録は営業 AI エージェントの自己申告なので、
 * 食い違いに気付くためだけに比べる</li>
 * </ul>
 */
@Component
class Reconciler {

	/** 決まった取り次ぎの道（C の act の並び）。保険会社のシステムに近い順。 */
	static final List<String> ROUTE = List.of("insurer-mcp", "sales-agent");

	private static final ObjectMapper JSON = new ObjectMapper();

	private final RecordSource source;

	Reconciler(RecordSource source) {
		this.source = source;
	}

	/** 確かめた点。 */
	record Check(String name, boolean ok, String detail) {
	}

	/** 契約ごとの突き合わせの結果。chain は、保険会社のシステムが受け取ったトークン（C）から遡った順である。 */
	record Report(String nonce, Map<String, Object> contract, boolean ok, String status, List<Check> checks,
			Map<String, Object> contractRecord, Map<String, Object> selfReport, List<Map<String, Object>> chain,
			Map<String, Object> tool, String thread, List<Map<String, Object>> conversation,
			List<Map<String, Object>> rejected) {
	}

	/** 一覧の 1 行。 */
	record Summary(String nonce, Map<String, Object> contract, boolean ok, String status) {
	}

	/** 新しい順に、契約の突き合わせの結果を返す。 */
	List<Summary> list(int limit) {
		List<Map<String, Object>> self = this.source.selfReported();
		Set<String> nonces = new LinkedHashSet<>();
		List<AuditEntry> logged = new ArrayList<>(this.source.contracts());
		logged.sort(Comparator.comparingLong(AuditEntry::at).reversed());
		for (AuditEntry e : logged) {
			if (e.writtenByOwner()) {
				nonces.add(str(map(e.get("contract")).get("nonce")));
			}
		}
		for (int i = self.size() - 1; i >= 0; i--) {
			nonces.add(str(map(self.get(i).get("contract")).get("nonce")));
		}
		List<Summary> out = new ArrayList<>();
		for (String nonce : nonces) {
			if (out.size() >= limit) {
				break;
			}
			Report r = reconcile(nonce, self);
			if (r != null) {
				out.add(new Summary(nonce, r.contract(), r.ok(), r.status()));
			}
		}
		return out;
	}

	Report reconcile(String nonce) {
		return reconcile(nonce, this.source.selfReported());
	}

	private Report reconcile(String nonce, List<Map<String, Object>> allSelf) {
		Seen seen = new Seen();
		List<AuditEntry> byNonce = seen.search(nonce);
		List<Map<String, Object>> contracts = byNonce.stream()
			.filter((e) -> e.writtenByOwner() && "contract".equals(e.kind())
					&& nonce.equals(map(e.get("contract")).get("nonce")))
			.map(AuditEntry::record)
			.toList();
		List<Map<String, Object>> self = allSelf.stream()
			.filter((s) -> nonce.equals(map(s.get("contract")).get("nonce")))
			.toList();
		if (contracts.isEmpty() && self.isEmpty()) {
			return null;
		}
		Map<String, Object> contractRecord = contracts.isEmpty() ? null : contracts.get(0);
		Map<String, Object> selfRecord = self.isEmpty() ? null : self.get(0);
		Map<String, Object> contract = map(
				(contractRecord != null) ? contractRecord.get("contract") : selfRecord.get("contract"));
		String customer = str(contract.get("customer"));
		List<Check> checks = new ArrayList<>();

		// 保険会社のシステムの自己申告と、Loki に残った契約の記録
		List<String> p = new ArrayList<>();
		if (contracts.size() != self.size()) {
			p.add("Loki の契約の記録が " + contracts.size() + " 件で、自己申告が " + self.size() + " 件である");
		}
		if (contracts.size() > 1 || self.size() > 1) {
			p.add("同じ nonce の契約が、複数ある");
		}
		if (contractRecord != null && selfRecord != null) {
			if (!canonical(contractRecord.get("contract")).equals(canonical(selfRecord.get("contract")))) {
				p.add("契約の中身が違う");
			}
			if (!Objects.equals(contractRecord.get("by"), selfRecord.get("by"))) {
				p.add("経由が違う");
			}
			if (!Objects.equals(contractRecord.get("token_jti"), selfRecord.get("tokenJti"))) {
				p.add("受け取ったトークンの jti が違う");
			}
			if (!Objects.equals(contractRecord.get("application_hash"), hash(selfRecord.get("application")))) {
				p.add("申込みのハッシュが違う");
			}
		}
		checks.add(check("自己申告と、契約の記録", p, "自己申告と、Loki の契約の記録が一致する"));

		// トークンの連鎖: C → B → A を、認可サーバーの記録で遡る
		String tokenJti = str((contractRecord != null) ? contractRecord.get("token_jti") : selfRecord.get("tokenJti"));
		List<AuditEntry> chain = new ArrayList<>();
		String missing = null;
		for (String jti = tokenJti; jti != null && chain.size() < 5;) {
			AuditEntry issued = issuedWith(seen, jti);
			if (issued == null) {
				missing = jti;
				break;
			}
			chain.add(issued);
			if ("issue".equals(issued.kind())) {
				break;
			}
			jti = str(issued.get("from_jti"));
		}
		List<String> route = chain.stream()
			.filter((e) -> "exchange".equals(e.kind()))
			.map((e) -> str(e.get("client")))
			.toList();
		p = new ArrayList<>();
		if (tokenJti == null) {
			p.add("契約の記録に、受け取ったトークンの jti がない");
		}
		else if (chain.isEmpty()) {
			p.add("保険会社のシステムが受け取ったトークン（jti " + tokenJti + "）を出した記録が、認可サーバーにない");
		}
		else {
			AuditEntry first = chain.get(chain.size() - 1);
			if (missing != null) {
				p.add("連鎖が途中で切れている（jti " + missing + " を出した記録がない）");
			}
			else if (!"issue".equals(first.kind()) || !"customer-app".equals(first.get("client"))) {
				p.add("最初のトークンが、顧客のアプリへのログインで出ていない");
			}
			if (chain.get(0).kind().equals("issue")) {
				p.add("保険会社のシステムが受け取ったのは、ログインで出した A そのものである");
			}
			else if (!route.equals(ROUTE)) {
				p.add("取り次ぎの道 " + route + " が、決まった道 " + ROUTE + " と違う");
			}
			if (chain.stream().anyMatch((e) -> !Objects.equals(customer, e.get("sub")))) {
				p.add("本人（sub）が、契約の顧客 " + customer + " と違う");
			}
		}
		checks.add(check("トークンの連鎖", p, "ログインの A から、交換の B と C まで、認可サーバーの記録でたどれる"));

		// 経由: 契約の記録の by と C の act を、交換の記録の道と比べる
		Object by = (contractRecord != null) ? contractRecord.get("by") : selfRecord.get("by");
		p = new ArrayList<>();
		if (!chain.isEmpty()) {
			if (!Objects.equals(by, route)) {
				p.add("契約の記録の経由 " + by + " が、交換の記録の道 " + route + " と違う");
			}
			List<String> act = actChain(chain.get(0).get("act"));
			if (!act.equals(route)) {
				p.add("C の act " + act + " が、交換の記録の道 " + route + " と違う");
			}
		}
		else {
			p.add("比べる交換の記録がない");
		}
		checks.add(check("経由", p, "契約の記録の経由と C の act が、交換の記録の道と一致する"));

		// 事務サービスのツールの記録
		AuditEntry tool = submitted(byNonce, nonce, str(contract.get("contractId")));
		p = new ArrayList<>();
		if (tool == null) {
			p.add("事務サービスに、この申込みを取り次いだ記録がない");
		}
		else {
			if (!Objects.equals(customer, tool.get("sub"))) {
				p.add("事務サービスへの依頼の本人（sub）" + tool.get("sub") + " が、契約の顧客と違う");
			}
			if (chain.size() == 3 && !Objects.equals(tool.get("jti"), chain.get(1).get("jti"))) {
				p.add("事務サービスが受け取ったトークンが、連鎖の B と違う");
			}
		}
		checks.add(check("事務サービスの記録", p, "事務サービスが、本人の依頼として、この申込みを取り次いだ"));

		// 申込みの中身: 根拠は、事務サービスが算出したハッシュ
		String applicationHash = (tool == null) ? null : str(tool.get("application_hash"));
		p = new ArrayList<>();
		if (tool == null) {
			p.add("比べる事務サービスの記録がない");
		}
		else {
			if (contractRecord != null && !Objects.equals(applicationHash, contractRecord.get("application_hash"))) {
				p.add("契約の記録の申込みのハッシュが、事務サービスが取り次いだ申込みと違う");
			}
			if (selfRecord != null && !Objects.equals(applicationHash, hash(selfRecord.get("application")))) {
				p.add("自己申告の申込みが、事務サービスが取り次いだ申込みと違う");
			}
			Object toolPlan = map(tool.get("plan")).get("id");
			Object contractPlan = map(contract.get("plan")).get("id");
			if (!Objects.equals(toolPlan, contractPlan)) {
				p.add("契約の案 " + contractPlan + " が、取り次いだ申込みの案 " + toolPlan + " と違う");
			}
			if (!Objects.equals(tool.get("customer"), customer)) {
				p.add("契約の顧客が、取り次いだ申込みの顧客と違う");
			}
		}
		checks.add(check("申込みの中身", p, "契約の案と申込みが、事務サービスが取り次いだ申込みと一致する"));

		// 会話: 営業 AI エージェントの自己申告。示した申込みのハッシュを、事務サービスのハッシュと比べ、食い違いに気付く
		String thread = byNonce.stream()
			.filter((e) -> e.writtenByOwner() && "conversation".equals(e.kind()))
			.map((e) -> str(e.get("thread")))
			.reduce((a, b) -> b)
			.orElse(null);
		List<Map<String, Object>> conversation = (thread == null) ? List.of()
				: seen.search(thread)
					.stream()
					.filter((e) -> e.writtenByOwner() && "conversation".equals(e.kind())
							&& thread.equals(e.get("thread")))
					.map(AuditEntry::record)
					.toList();
		String shown = conversation.stream()
			.filter((r) -> "present_application".equals(r.get("name")) && r.get("document_hash") != null)
			.map((r) -> str(r.get("document_hash")))
			.reduce((a, b) -> b)
			.orElse(null);
		String note;
		p = new ArrayList<>();
		if (thread == null) {
			note = "会話の記録がない（営業 AI エージェントとの会話を通らない申込み）";
		}
		else if (shown == null || applicationHash == null) {
			note = "比べる申込みの提示か、事務サービスの記録がない";
		}
		else if (shown.equals(applicationHash)) {
			note = "会話で示した申込みと、取り次いだ申込みのハッシュが同じ";
		}
		else {
			note = "";
			p.add("会話で示した申込みと、事務サービスが取り次いだ申込みのハッシュが違う");
		}
		checks.add(check("会話（営業 AI エージェントの自己申告。確かめていない）", p, note));

		// 書いた者が合わない記録（記録の偽装）。受け付けず、食い違いとして示す
		List<Map<String, Object>> rejected = seen.rejected();
		p = rejected.stream()
			.map((r) -> r.get("kind") + " の記録を " + r.get("app") + "（" + r.get("container") + "）が書いた。書いてよいのは "
					+ r.get("expected") + " だけ")
			.toList();
		checks.add(check("書いた者", p, "関わる記録は、全て書いてよい者が書いた"));

		boolean ok = checks.stream().allMatch(Check::ok);
		return new Report(nonce, contract, ok, ok ? "食い違いなし" : "食い違いあり", checks, contractRecord, selfRecord,
				chain.stream().map(AuditEntry::record).toList(), (tool == null) ? null : tool.record(), thread,
				conversation, rejected);
	}

	/** その jti のトークンを出した、認可サーバーの記録。 */
	private static AuditEntry issuedWith(Seen seen, String jti) {
		return seen.search(jti)
			.stream()
			.filter((e) -> e.writtenByOwner() && ("exchange".equals(e.kind()) || "issue".equals(e.kind()))
					&& jti.equals(e.get("jti")))
			.findFirst()
			.orElse(null);
	}

	/** 事務サービスの submit_application の記録。契約の番号が合うものを選び、なければ通ったものの最後を選ぶ。 */
	private static AuditEntry submitted(List<AuditEntry> byNonce, String nonce, String contractId) {
		List<AuditEntry> tools = byNonce.stream()
			.filter((e) -> e.writtenByOwner() && "tool_call".equals(e.kind())
					&& "submit_application".equals(e.get("tool")) && nonce.equals(e.get("nonce")))
			.toList();
		return tools.stream()
			.filter((e) -> contractId != null && contractId.equals(e.get("contractId")))
			.findFirst()
			.orElse(tools.stream()
				.filter((e) -> Objects.equals(200, e.get("status")))
				.reduce((a, b) -> b)
				.orElse(null));
	}

	/** act の入れ子を、外側（保険会社のシステムに近い者）から並べる。 */
	static List<String> actChain(Object act) {
		List<String> chain = new ArrayList<>();
		for (Map<String, Object> a = map(act); !a.isEmpty(); a = map(a.get("act"))) {
			chain.add(str(a.get("sub")));
		}
		return chain;
	}

	private static Check check(String name, List<String> problems, String okDetail) {
		return problems.isEmpty() ? new Check(name, true, okDetail) : new Check(name, false, String.join("。", problems));
	}

	/** JCS（RFC 8785）で正規化した内容の SHA-256 の base64url。事務サービスと保険会社のシステムと同じ算出（D-32）。 */
	static String hash(Object value) {
		if (value == null) {
			return null;
		}
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical(value).getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	static String canonical(Object value) {
		try {
			return new JsonCanonicalizer(JSON.writeValueAsString(value)).getEncodedString();
		}
		catch (Exception ex) {
			throw new IllegalArgumentException("正規化できない", ex);
		}
	}

	@SuppressWarnings("unchecked")
	static Map<String, Object> map(Object value) {
		return (value instanceof Map<?, ?> m) ? (Map<String, Object>) m : Map.of();
	}

	static String str(Object value) {
		return (value == null) ? null : value.toString();
	}

	/** 1 つの突き合わせの間に読んだ記録。同じ問い合わせを繰り返さず、書いた者が合わない記録を集める。 */
	private final class Seen {

		private final Map<String, List<AuditEntry>> cache = new HashMap<>();

		private final Map<String, Map<String, Object>> rejected = new LinkedHashMap<>();

		List<AuditEntry> search(String needle) {
			return this.cache.computeIfAbsent(needle, (n) -> {
				List<AuditEntry> found = Reconciler.this.source.search(n);
				for (AuditEntry e : found) {
					if (!e.writtenByOwner()) {
						Map<String, Object> r = new LinkedHashMap<>();
						r.put("kind", e.kind());
						r.put("app", e.app());
						r.put("container", e.container());
						r.put("expected", e.expectedWriter());
						r.put("record", e.record());
						this.rejected.putIfAbsent(e.at() + "/" + e.app() + "/" + canonical(e.record()), r);
					}
				}
				return found;
			});
		}

		List<Map<String, Object>> rejected() {
			return List.copyOf(this.rejected.values());
		}

	}

}
