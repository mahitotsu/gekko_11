package jp.gekko11.insurerauth;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * 利用者の passkey の公開鍵を、ログインサーバー（Keycloak）の管理の API から読む（D-42）。
 * passkey は、ログインとの申込みの署名で同じものを使い、ログインサーバーだけが登録を持つ。
 * 認可サーバーは、JWT-SVID でクライアント認証し、利用者を読む権限（view-users）だけを持つ。
 */
@Component
class LoginDirectory {

	private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

	private static final String PASSKEY = "webauthn-passwordless";

	private final AuthProperties props;

	private final RestClient client;

	private final ObjectMapper json = new ObjectMapper();

	private String token;

	private Instant expires = Instant.EPOCH;

	LoginDirectory(AuthProperties props) {
		this.props = props;
		this.client = RestClient.create(props.loginUrl());
	}

	/** 管理の API のトークン。期限の 30 秒前まで使い回す。 */
	private synchronized String token() throws Exception {
		if (this.token != null && Instant.now().isBefore(this.expires)) {
			return this.token;
		}
		LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("grant_type", "client_credentials");
		form.add("client_id", "insurer-auth");
		form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe");
		form.add("client_assertion", Files.readString(Path.of(this.props.jwtSvidFile())).trim());
		Map<String, Object> body = this.client.post()
			.uri("/realms/insurer/protocol/openid-connect/token")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body(form)
			.retrieve()
			.body(new ParameterizedTypeReference<Map<String, Object>>() {
			});
		this.token = String.valueOf(body.get("access_token"));
		this.expires = Instant.now().plusSeconds(((Number) body.get("expires_in")).longValue() - 30);
		return this.token;
	}

	/** ログインサーバーにある、利用者の ID と passkey の資格情報。利用者がいなければ、ID は空で、一覧も空。 */
	record Credentials(String userId, List<Map<String, Object>> passkeys) {
	}

	Credentials credentialsOf(String user) throws Exception {
		String bearer = "Bearer " + token();
		List<Map<String, Object>> users = this.client.get()
			.uri("/admin/realms/insurer/users?username={u}&exact=true", user)
			.header("Authorization", bearer)
			.retrieve()
			.body(new ParameterizedTypeReference<List<Map<String, Object>>>() {
			});
		if (users == null || users.isEmpty()) {
			return new Credentials("", List.of());
		}
		String id = String.valueOf(users.get(0).get("id"));
		List<Map<String, Object>> credentials = this.client.get()
			.uri("/admin/realms/insurer/users/{id}/credentials", id)
			.header("Authorization", bearer)
			.retrieve()
			.body(new ParameterizedTypeReference<List<Map<String, Object>>>() {
			});
		return new Credentials(id, credentials.stream().filter((c) -> PASSKEY.equals(c.get("type"))).toList());
	}

	/** 利用者の passkey の公開鍵の一覧。各要素は id（base64url）と coseKey（base64url の CBOR）。保険会社のシステムの形と同じ。 */
	List<Map<String, String>> keysOf(String user) throws Exception {
		return credentialsOf(user).passkeys().stream().map((c) -> keyOf(c.get("credentialData"))).toList();
	}

	/**
	 * 本人に見せる passkey の一覧（D-43）。利用者の ID（passkey の user handle）と、各 passkey の識別子、ログインサーバーの中の ID、名前、作った時刻（ミリ秒）。
	 * 画面は、識別子の一覧を Signal API で端末に伝え、署名を頼むときにも指定する。公開鍵は返さない。
	 */
	Map<String, Object> listOf(String user) throws Exception {
		Credentials found = credentialsOf(user);
		List<Map<String, Object>> passkeys = found.passkeys().stream().map((c) -> {
			Map<String, Object> item = new java.util.LinkedHashMap<>();
			item.put("id", keyOf(c.get("credentialData")).get("id"));
			// ログインサーバーの中の資格情報の ID。本人が消すときに、ログインサーバーへ渡す（delete_credential。D-43）
			item.put("ref", String.valueOf(c.get("id")));
			item.put("label", String.valueOf(c.getOrDefault("userLabel", "")));
			item.put("created", c.getOrDefault("createdDate", 0));
			return item;
		}).toList();
		return Map.of("userHandle", B64URL.encodeToString(found.userId().getBytes(java.nio.charset.StandardCharsets.UTF_8)), "passkeys", passkeys);
	}

	/** ログインサーバーの資格情報の credentialData（JSON の文字列）から、識別子と公開鍵を取り出す。 */
	Map<String, String> keyOf(Object credentialData) {
		try {
			Map<?, ?> data = this.json.readValue(String.valueOf(credentialData), Map.class);
			return Map.of("id", B64URL.encodeToString(decode(data.get("credentialId"))), "coseKey",
					B64URL.encodeToString(decode(data.get("credentialPublicKey"))));
		}
		catch (Exception ex) {
			throw new IllegalStateException("passkey の公開鍵を読めない: " + ex.getMessage(), ex);
		}
	}

	/** base64 と base64url のどちらでも読む（ログインサーバーの版で、書き方が違う）。 */
	private static byte[] decode(Object value) {
		if (value == null) {
			throw new IllegalArgumentException("値がない");
		}
		return Base64.getDecoder().decode(String.valueOf(value).replaceAll("\\s", "").replace('-', '+').replace('_', '/'));
	}

}
