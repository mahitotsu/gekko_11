package jp.gekko11.insurerbackend;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * 契約内容を、営業 AI エージェントを経ずに、顧客の登録済みの連絡先へ直接送る（P-8、P-14）。
 * 登録済みの連絡先は、顧客のアプリへの出口（Envoy が SVID で mTLS をかける）の先にある。
 * 送った記録は、届いたかどうかと一緒に残す。
 */
@Component
class Notifier {

	private final Store store;

	private final RestClient client;

	private final String customerAppUrl;

	Notifier(Store store, BackendProperties props) {
		this.store = store;
		SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
		factory.setConnectTimeout(Duration.ofMillis(1500));
		factory.setReadTimeout(Duration.ofMillis(1500));
		this.client = RestClient.builder().requestFactory(factory).build();
		this.customerAppUrl = props.customerAppUrl();
	}

	/** 登録した全ての宛先へ送る。宛先がなければ送らず、届かなかった記録だけを残す。 */
	void send(java.util.List<String> to, Map<String, Object> notice) {
		if (to.isEmpty()) {
			this.store.outbox.add(new Store.Delivery("(連絡先の登録がない)", notice, false));
		}
		to.forEach((each) -> sendOne(each, notice));
	}

	private void sendOne(String to, Map<String, Object> notice) {
		String url = to.startsWith("/") ? this.customerAppUrl + to : to;
		boolean delivered;
		try {
			delivered = this.client.post().uri(url).body(notice).retrieve().toBodilessEntity().getStatusCode()
				.is2xxSuccessful();
		}
		catch (RuntimeException ex) {
			delivered = false;
		}
		this.store.outbox.add(new Store.Delivery(to, notice, delivered));
	}

}
