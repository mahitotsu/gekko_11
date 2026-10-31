package jp.gekko11.insurerauth;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/** 登録を外したクライアント。新しいトークンを出さず、出したトークンも有効性の問い合わせで無効にする（D4、D10）。 */
@Component
class ClientRevocation {

	private final Set<String> revoked = ConcurrentHashMap.newKeySet();

	boolean isRevoked(String clientId) {
		return this.revoked.contains(clientId);
	}

	void revoke(String clientId) {
		this.revoked.add(clientId);
	}

	void restore(String clientId) {
		this.revoked.remove(clientId);
	}

}
