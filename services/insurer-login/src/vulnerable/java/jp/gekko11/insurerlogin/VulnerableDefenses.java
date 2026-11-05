package jp.gekko11.insurerlogin;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.keycloak.Config;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.util.JsonSerialization;

/**
 * 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
 * 防御を、実行中に外す。管理のポートで、GET で今の設定を返し、PUT で置き換える。
 * 製品が起動のときに初期化する部品として登録するだけで、イベントは受け取らない。
 */
public final class VulnerableDefenses implements EventListenerProviderFactory {

	private static final List<String> KNOWN = List.of(Defenses.AUD_ONE, Defenses.SHORT_TTL, Defenses.ID_TOKEN_AUD);

	private static final int PORT = 9091;

	private final Map<String, String> off = new ConcurrentHashMap<>();

	private HttpServer server;

	@Override
	public void init(Config.Scope config) {
		Defenses.use((id) -> !this.off.containsKey(id));
		try {
			this.server = HttpServer.create(new InetSocketAddress(PORT), 0);
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
		this.server.createContext("/defenses", this::handle);
		this.server.start();
	}

	@SuppressWarnings("unchecked")
	private void handle(HttpExchange exchange) throws IOException {
		if ("PUT".equals(exchange.getRequestMethod())) {
			Map<String, Object> body = JsonSerialization.readValue(exchange.getRequestBody(), Map.class);
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

	private static void reply(HttpExchange exchange, int status, Object body) throws IOException {
		byte[] bytes = JsonSerialization.writeValueAsBytes(body);
		exchange.getResponseHeaders().set("content-type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length);
		exchange.getResponseBody().write(bytes);
		exchange.close();
	}

	@Override
	public EventListenerProvider create(KeycloakSession session) {
		return new EventListenerProvider() {
			@Override
			public void onEvent(Event event) {
			}

			@Override
			public void onEvent(AdminEvent event, boolean includeRepresentation) {
			}

			@Override
			public void close() {
			}
		};
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
		this.server.stop(0);
	}

	@Override
	public String getId() {
		return "insurer-vulnerable-defenses";
	}

}
