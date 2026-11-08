// 名前空間、入口の名前、発行者、ポートなど、全てのマニフェストが使う値。

export const TRUST_DOMAIN = "gekko11.internal";
export const ns = process.argv[2];
if (ns !== "secure" && ns !== "vulnerable") throw new Error("名前空間は secure か vulnerable");
export const vulnerable = ns === "vulnerable";

export const IMAGES = {
  envoy: "envoyproxy/envoy:v1.31.5",
  loki: "grafana/loki:3.7.8",
  helper: "ghcr.io/spiffe/spiffe-helper:0.12.2",
  auth: `gekko11/insurer-auth:${ns}`,
  login: `gekko11/insurer-login:${ns}`,
  backend: `gekko11/insurer-backend:${ns}`,
  audit: "gekko11/insurer-audit:dev",
  mcp: "gekko11/insurer-mcp:dev",
  node: `gekko11/node:${ns}`,
};

export const spiffeId = (sa: string) => `spiffe://${TRUST_DOMAIN}/ns/${ns}/sa/${sa}`;
export const host = (service: string) => `${service}.${ns}.svc`;

/**
 * クラスタの入口（D-25）。ブラウザは、名前空間ごとのポートで、app、login、auth、audit の名前に届く。
 * 入口の名前は、ここだけで決める。RP ID、origin、issuer、戻り先、CORS は、ここから作る。
 */
export const ENTRANCE = { domain: "localhost", port: vulnerable ? 8082 : 8081, nodePort: vulnerable ? 30082 : 30081, listen: 8080 };
export type PublicName = "app" | "login" | "auth" | "audit";
export const publicHost = (name: PublicName) => `${name}.${ns}.${ENTRANCE.domain}`;
export const publicOrigin = (name: PublicName) => `http://${publicHost(name)}:${ENTRANCE.port}`;
/** 認可サーバーの iss（B と C）。 */
export const ISSUER = publicOrigin("auth");
/** ログインサーバーの iss（A、P、ID トークン。D-35）。 */
export const LOGIN_ISSUER = `${publicOrigin("login")}/realms/insurer`;
/** ログインサーバーの公開鍵を、Envoy の出口から取るポートとパス。 */
export const LOGIN_EGRESS = 15105;
export const LOGIN_JWKS_URL = `http://127.0.0.1:${LOGIN_EGRESS}/realms/insurer/protocol/openid-connect/certs`;
export const AUTH_JWKS_URL = "http://127.0.0.1:15101/oauth2/jwks";
export const CUSTOMER_ORIGIN = publicOrigin("app");
/** 営業 AI エージェントの内部の名前。BFF は、DPoP の htu に、この名前とパスを使う（D-41）。 */
export const AGENT_INTERNAL = `https://${host("sales-agent")}:8443`;
/** passkey の RP ID と、署名した画面の origin（顧客のアプリ）。 */
// passkey は、ログインと申込みの署名で同じものを使う。RP ID は、ログインサーバーと顧客のアプリの共通の親の名前にする（D-42）。
// 申込みの署名は、顧客のアプリの origin だけで受け付け、ログインの署名を使い回させない
export const WEBAUTHN = { RP_ID: `${ns}.${ENTRANCE.domain}`, WEBAUTHN_ORIGINS: CUSTOMER_ORIGIN };

/** 防御を外す管理のポート（vulnerable だけ）。token-guard と、アプリ。 */
export const ADMIN = { tokenGuard: 9090, app: 9091 };
