package jp.gekko11.insurerauth;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 認可サーバーの設定。
 *
 * @param issuer トークンの iss
 * @param trustDomain SPIFFE の信頼ドメイン
 * @param namespace サービスを置く名前空間（SPIFFE ID の ns）
 * @param loginIssuer ログインサーバーの iss（交換で受け取る A と、passkey の受け口で受け取る P を出す者）
 * @param loginJwksUrl ログインサーバーの公開鍵（Envoy の出口を通す）
 * @param rpId passkey の RP ID
 * @param origins passkey の登録と署名を受け付ける origin
 */
@ConfigurationProperties("gekko")
public record AuthProperties(String issuer, String trustDomain, String namespace, String loginIssuer,
		String loginJwksUrl, String rpId, java.util.List<String> origins) {

	/** サービスの SPIFFE ID（D-20 の形）。 */
	public String spiffeId(String service) {
		return "spiffe://" + this.trustDomain + "/ns/" + this.namespace + "/sa/" + service;
	}

}
