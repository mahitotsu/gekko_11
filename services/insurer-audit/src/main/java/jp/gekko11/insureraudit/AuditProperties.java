package jp.gekko11.insureraudit;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 監査サービスの設定。
 *
 * @param namespace サービスを置く名前空間（Loki の記録の印）
 * @param issuer ログインサーバーの iss（ID トークンの iss。ブラウザは、この名前でログインする）
 * @param publicOrigin 監査サービスの公開名（ログインの戻り先）
 * @param loginUrl ログインサーバーへの出口（Envoy が相手の SPIFFE ID を確かめる）
 * @param jwtSvidFile ログインサーバーへのクライアント認証に示す JWT-SVID のファイル（spiffe-helper が更新する）
 * @param backendUrl 保険会社のシステムへの出口（同上）
 * @param lokiUrl 名前空間の Loki
 */
@ConfigurationProperties("gekko")
public record AuditProperties(String namespace, String issuer, String publicOrigin, String loginUrl, String jwtSvidFile,
		String backendUrl, String lokiUrl) {

}
