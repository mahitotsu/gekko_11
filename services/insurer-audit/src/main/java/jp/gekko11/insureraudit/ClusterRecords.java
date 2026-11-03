package jp.gekko11.insureraudit;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * 記録を、名前空間の Loki と、保険会社のシステムの自己申告から読む（D-30）。
 * Loki は、名前空間の中の HTTP で読む（読めるのは監査サービスだけ。NetworkPolicy）。保険会社のシステムは、Envoy の出口から、
 * 監査サービスの SVID で呼ぶ。
 */
@Component
class ClusterRecords implements RecordSource {

	/** Loki の保存期間（7 日）と同じだけ遡る。 */
	private static final Duration RETENTION = Duration.ofDays(7);

	private static final int LIMIT = 5000;

	private static final ObjectMapper JSON = new ObjectMapper();

	private final AuditProperties props;

	private final RestClient http = RestClient.create();

	ClusterRecords(AuditProperties props) {
		this.props = props;
	}

	@Override
	public List<AuditEntry> search(String needle) {
		return query("|= " + quote(needle));
	}

	@Override
	public List<AuditEntry> contracts() {
		// 事務サービス（Python）の記録は「": "」で区切るので、空白の有無を問わない
		return query("|~ " + quote("\"kind\": ?\"contract\""));
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Map<String, Object>> selfReported() {
		Map<String, Object> body = this.http.get()
			.uri(this.props.backendUrl() + "/audit/records")
			.retrieve()
			.body(Map.class);
		return (body == null) ? List.of() : (List<Map<String, Object>>) body.getOrDefault("contracts", List.of());
	}

	@SuppressWarnings("unchecked")
	private List<AuditEntry> query(String filter) {
		Instant now = Instant.now();
		String logql = "{namespace=" + quote(this.props.namespace()) + "} " + filter;
		// LogQL の { } を、URI の雛形の変数と取り違えないよう、値は変数として渡して符号化する
		var uri = UriComponentsBuilder.fromUriString(this.props.lokiUrl() + "/loki/api/v1/query_range")
			.queryParam("query", "{query}")
			.queryParam("start", nanos(now.minus(RETENTION)))
			.queryParam("end", nanos(now.plusSeconds(60)))
			.queryParam("limit", LIMIT)
			.queryParam("direction", "forward")
			.encode()
			.buildAndExpand(logql)
			.toUri();
		Map<String, Object> body = this.http.get().uri(uri).retrieve().body(Map.class);
		List<AuditEntry> entries = new ArrayList<>();
		Map<String, Object> data = (body == null) ? Map.of() : (Map<String, Object>) body.get("data");
		for (Map<String, Object> stream : (List<Map<String, Object>>) data.getOrDefault("result", List.of())) {
			Map<String, String> labels = (Map<String, String>) stream.get("stream");
			for (List<String> value : (List<List<String>>) stream.get("values")) {
				Map<String, Object> record = parse(value.get(1));
				if (record != null) {
					entries.add(new AuditEntry(labels.get("app"), labels.get("container"), Long.parseLong(value.get(0)),
							record));
				}
			}
		}
		entries.sort(Comparator.comparingLong(AuditEntry::at));
		return entries;
	}

	/** 1 行の JSON の "audit" の欄。形が違う行は読まない。 */
	@SuppressWarnings("unchecked")
	private static Map<String, Object> parse(String line) {
		try {
			Object audit = JSON.readValue(line, Map.class).get("audit");
			return (audit instanceof Map<?, ?> m && m.get("kind") instanceof String) ? (Map<String, Object>) m : null;
		}
		catch (Exception ex) {
			return null;
		}
	}

	private static String nanos(Instant t) {
		return t.getEpochSecond() + String.format("%09d", t.getNano());
	}

	/** LogQL の文字列。 */
	private static String quote(String s) {
		return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
	}

}
