package jp.gekko11.insurerbackend;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 保険会社のシステムの設定。
 *
 * @param trustDomain SPIFFE の信頼ドメイン
 * @param namespace サービスを置く名前空間
 * @param authUrl 認可サーバーへの出口（Envoy が SVID で mTLS をかける）
 * @param customerAppUrl 顧客のアプリへの出口（直送の宛先）
 * @param rpId passkey の RP ID
 * @param origins 署名した画面の origin（顧客のアプリ）
 */
@ConfigurationProperties("gekko")
public record BackendProperties(String trustDomain, String namespace, String authUrl, String customerAppUrl,
		String rpId, List<String> origins) {

	public String spiffeId(String service) {
		return "spiffe://" + this.trustDomain + "/ns/" + this.namespace + "/sa/" + service;
	}

}
