package jp.gekko11.insurerbackend;

import java.util.List;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * 顧客が登録した連絡先（受信箱の番号）を、認可サーバーから引く（P-14、D-26）。直送の宛先は、申込みに書かれた連絡先ではなく、これにする（D18）。
 * 認可サーバーは、相手の SPIFFE ID で呼び出しを限る。
 */
interface ContactDirectory {

	/** 受信箱の番号（端末ごと）。登録がなければ空。 */
	List<String> inboxesOf(String user);

	@Component
	class FromAuthServer implements ContactDirectory {

		private final RestClient auth;

		FromAuthServer(BackendProperties props) {
			this.auth = RestClient.create(props.authUrl());
		}

		@Override
		public List<String> inboxesOf(String user) {
			Map<String, List<String>> body = this.auth.get().uri("/internal/contacts/{user}", user).retrieve().body(
					new ParameterizedTypeReference<>() {
					});
			return (body == null) ? List.of() : body.getOrDefault("inboxes", List.of());
		}

	}

}
