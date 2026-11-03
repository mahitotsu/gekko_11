package jp.gekko11.insureraudit;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 監査サービスの設定。
 *
 * @param namespace サービスを置く名前空間（Loki の記録の印）
 * @param issuer 認可サーバーの公開名（ID トークンの iss。ブラウザは、この名前でログインする）
 * @param publicOrigin 監査サービスの公開名（ログインの戻り先）
 * @param authUrl 認可サーバーへの出口（Envoy が SVID で mTLS をかける）
 * @param backendUrl 保険会社のシステムへの出口（同上）
 * @param lokiUrl 名前空間の Loki
 */
@ConfigurationProperties("gekko")
public record AuditProperties(String namespace, String issuer, String publicOrigin, String authUrl, String backendUrl,
		String lokiUrl) {

}
