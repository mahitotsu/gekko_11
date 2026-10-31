package jp.gekko11.insurerauth;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 認可サーバーの設定。
 *
 * @param issuer トークンの iss
 * @param trustDomain SPIFFE の信頼ドメイン
 * @param namespace サービスを置く名前空間（SPIFFE ID の ns）
 * @param customerRedirectUri 顧客のアプリの戻り先
 */
@ConfigurationProperties("gekko")
public record AuthProperties(String issuer, String trustDomain, String namespace, String customerRedirectUri) {

	/** サービスの SPIFFE ID（D-20 の形）。 */
	public String spiffeId(String service) {
		return "spiffe://" + this.trustDomain + "/ns/" + this.namespace + "/sa/" + service;
	}

}
