package jp.gekko11.insurerauth;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

/**
 * 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
 * 防御を、実行中に外す。管理のポートで、GET で今の設定を返し、PUT で置き換える。
 */
@Component
@Primary
class VulnerableDefenses implements Defenses {

	private static final List<String> KNOWN = List.of(AUD_ONE, SHORT_TTL, KEEP_ACT, NARROW_TERMS, FIXED_TARGET,
			VERIFY_SUBJECT);

	private final Map<String, String> off = new ConcurrentHashMap<>();

	private final ObjectMapper json = new ObjectMapper();

	private final int port;

	private HttpServer server;

	VulnerableDefenses(@Value("${gekko.defense-admin-port:9091}") int port) {
		this.port = port;
	}

	@Override
	public boolean enabled(String id) {
		return !this.off.containsKey(id);
	}

	@PostConstruct
	void start() throws IOException {
		this.server = HttpServer.create(new InetSocketAddress(this.port), 0);
		this.server.createContext("/defenses", this::handle);
		this.server.start();
	}

	@PreDestroy
	void stop() {
		this.server.stop(0);
	}

	@SuppressWarnings("unchecked")
	private void handle(HttpExchange exchange) throws IOException {
		if ("PUT".equals(exchange.getRequestMethod())) {
			Map<String, Object> body = this.json.readValue(exchange.getRequestBody(), Map.class);
			Map<String, String> next = (Map<String, String>) body.getOrDefault("off", Map.of());
			List<String> unknown = next.keySet().stream().filter((id) -> !KNOWN.contains(id)).toList();
			if (!unknown.isEmpty()) {
				reply(exchange, 400, Map.of("error", "知らない防御: " + String.join(",", unknown)));
				return;
			}
			this.off.clear();
			this.off.putAll(next);
		}
		reply(exchange, 200, Map.of("off", this.off));
	}

	private void reply(HttpExchange exchange, int status, Object body) throws IOException {
		byte[] bytes = this.json.writeValueAsBytes(body);
		exchange.getResponseHeaders().set("content-type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length);
		exchange.getResponseBody().write(bytes);
		exchange.close();
	}

}
