package jp.gekko11.insurerbackend;

import java.util.List;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** 顧客が登録した passkey の公開鍵を、認可サーバーから引く（4-5）。認可サーバーは、相手の SPIFFE ID で呼び出しを限る。 */
interface PasskeyDirectory {

	/** 登録した passkey の一覧。各要素は id（base64url）と coseKey（base64url の CBOR）。 */
	List<Map<String, String>> keysOf(String user);

	@Component
	class FromAuthServer implements PasskeyDirectory {

		private final RestClient auth;

		FromAuthServer(BackendProperties props) {
			this.auth = RestClient.create(props.authUrl());
		}

		@Override
		public List<Map<String, String>> keysOf(String user) {
			return this.auth.get().uri("/internal/passkeys/{user}", user).retrieve().body(new ParameterizedTypeReference<>() {
			});
		}

	}

}
