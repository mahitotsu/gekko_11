// サービスの一覧（architecture の 2-1 の経路）、確かめの役、ServiceAccount。

import { ADMIN, AGENT_INTERNAL, CUSTOMER_ORIGIN, ENTRANCE, IMAGES, ISSUER, LOGIN_EGRESS, LOGIN_ISSUER, TRUST_DOMAIN, WEBAUTHN, host, ns, publicHost, publicOrigin, vulnerable } from "./common.ts";

export type Name = "sales-agent" | "insurer-mcp" | "insurer-backend" | "customer-app" | "insurer-audit" | "insurer-login";

export interface Egress {
  port: number;
  target: Name | "insurer-auth";
  /** token-guard が、受け口で確かめたトークンを、次の段のトークンに替えて付ける。 */
  exchange?: boolean;
  /** 相手に送る Host。既定は相手の内部の名前。ログインサーバーは、DPoP の htu を Host で照らすので、公開名を送る。 */
  host?: string;
}

export interface Service {
  name: Name;
  /** 受け口: dpop は顧客（証明書なし）から、mtls はサービスから、open はトークンなしで相手の SPIFFE ID を見る。 */
  ingress: "dpop" | "mtls" | "open";
  port: number;
  /** DPoP の受け口でも、相手の証明書を求める（営業 AI エージェントは、顧客のアプリの BFF からだけ受ける。D-41）。 */
  clientCert?: boolean;
  /** トークンを見ない受け口で、サービスから mTLS で受けるポート（顧客のアプリの直送の受け口）。 */
  mtlsPort?: number;
  /** 呼んでよい相手（G27、NetworkPolicy）。probe は、確かめのために全てを呼べる。 */
  callers: string[];
  /** トークンを確かめず、相手の証明書の情報（XFCC）をアプリに渡す経路。 */
  openPaths?: string[];
  egress: Egress[];
  app: {
    image: string;
    command: string[];
    env?: Record<string, string | undefined>;
    /** Java のアプリのメモリ。既定は 256Mi から 512Mi。 */
    memory?: { requests: string; limits: string };
    /** JWT-SVID をファイルで受け取る（監査サービスと顧客のアプリ。D-38、D-41）。 */
    jwtSvid?: boolean;
    /** SPIRE の bundle の受け口の証明書を信頼する（ログインサーバー。D-38）。 */
    bundleCa?: boolean;
  };
}

/** vulnerable だけ: G29 を外すと、もう一方の発行者の公開鍵も使う。 */
export const anyIssuerEgress: Egress[] = vulnerable ? [{ port: LOGIN_EGRESS, target: "insurer-login" }] : [];

/** 2 章の経路（architecture の 2-1）。 */
export const SERVICES: Service[] = [
  {
    name: "sales-agent",
    ingress: "dpop",
    clientCert: true,
    port: 8443,
    // 顧客のアプリの BFF だけが、A と DPoP の proof を付けて呼ぶ（D-41）
    callers: ["customer-app"],
    egress: [
      { port: 15101, target: "insurer-auth" },
      { port: 15102, target: "insurer-mcp", exchange: true },
      // A を確かめる公開鍵を、ログインサーバーから取る
      { port: LOGIN_EGRESS, target: "insurer-login" },
    ],
    app: {
      image: IMAGES.node,
      command: ["node", "packages/sales-agent/src/server.ts"],
      env: { HOME: "/tmp", MCP_EGRESS_URL: "http://127.0.0.1:15102/mcp" },
    },
  },
  {
    name: "insurer-mcp",
    ingress: "mtls",
    port: 9443,
    callers: ["sales-agent"],
    egress: [
      { port: 15101, target: "insurer-auth" },
      { port: 15102, target: "insurer-backend", exchange: true },
      ...anyIssuerEgress,
    ],
    app: { image: IMAGES.mcp, command: ["python", "-m", "insurer_mcp.app"], env: { NAMESPACE: ns } },
  },
  {
    name: "insurer-backend",
    ingress: "mtls",
    port: 9443,
    callers: ["insurer-mcp"],
    // 監査の記録（相手の SPIFFE ID で限る）と、提示の公開鍵（顧客のアプリのサーバーが取る）は、トークンなしで受ける
    openPaths: ["/audit/", "/offers-jwks.json"],
    egress: [
      { port: 15101, target: "insurer-auth" },
      { port: 15103, target: "customer-app" },
      ...anyIssuerEgress,
    ],
    app: {
      image: IMAGES.backend,
      command: ["java", "-jar", "/app/insurer-backend.jar"],
      env: { NAMESPACE: ns, TRUST_DOMAIN, ...WEBAUTHN },
    },
  },
  {
    name: "customer-app",
    ingress: "open",
    port: 8443,
    mtlsPort: 9443,
    callers: ["insurer-backend"],
    egress: [
      // 提示の公開鍵を、保険会社のシステムから取り、画面に渡す（4-5）
      { port: 15104, target: "insurer-backend" },
      // BFF（D-41）: ログインサーバーで A と P を受け取り、営業 AI エージェントと認可サーバーを、顧客の代わりに呼ぶ
      { port: LOGIN_EGRESS, target: "insurer-login", host: `${publicHost("login")}:${ENTRANCE.port}` },
      { port: 15106, target: "sales-agent" },
      { port: 15101, target: "insurer-auth" },
    ],
    app: {
      image: IMAGES.node,
      command: ["node", "packages/customer-app/src/server.ts"],
      env: { NAMESPACE: ns, TRUST_DOMAIN, ISSUER: LOGIN_ISSUER, AUTH_ORIGIN: publicOrigin("auth"), RP_ID: WEBAUTHN.RP_ID, APP_ORIGIN: CUSTOMER_ORIGIN, LOGIN_URL: `http://127.0.0.1:${LOGIN_EGRESS}`, AGENT_URL: "http://127.0.0.1:15106", AGENT_ORIGIN_INTERNAL: AGENT_INTERNAL, AUTH_URL: "http://127.0.0.1:15101", AUTH_ORIGIN_INTERNAL: `https://${host("insurer-auth")}:8443`, JWT_SVID_FILE: "/svid/jwt_svid.token", APP_ADMIN_PORT: String(ADMIN.app) },
      jwtSvid: true,
    },
  },
  {
    // 監査サービス（D-17、D-31）。監査の担当のブラウザから入口を通って受け、ログインサーバーと保険会社のシステムは、SVID で呼ぶ。
    // 記録は、名前空間の Loki から読む（D-30）
    name: "insurer-audit",
    ingress: "open",
    port: 8443,
    callers: [],
    egress: [
      { port: LOGIN_EGRESS, target: "insurer-login" },
      { port: 15102, target: "insurer-backend" },
    ],
    app: {
      image: IMAGES.audit,
      command: ["java", "-jar", "/app/insurer-audit.jar"],
      env: {
        NAMESPACE: ns,
        ISSUER: LOGIN_ISSUER,
        PUBLIC_ORIGIN: publicOrigin("audit"),
        LOGIN_EGRESS_URL: `http://127.0.0.1:${LOGIN_EGRESS}`,
        LOKI_URL: `http://${host("loki")}.cluster.local:3100`,
      },
      jwtSvid: true,
    },
  },
  {
    // ログインサーバー（Keycloak。D-35）。ブラウザから入口を通って受ける。公開鍵は、確かめる者が SPIFFE ID を確かめて取る
    name: "insurer-login",
    ingress: "open",
    port: 8443,
    callers: ["sales-agent", "insurer-audit", "insurer-auth", "customer-app", ...(vulnerable ? ["insurer-mcp", "insurer-backend"] : [])],
    egress: [],
    app: {
      image: IMAGES.login,
      // 画面のスクリプトは、配置で替わっても URL が変わらない。ブラウザに古いものを使わせないよう、キャッシュさせない
      command: ["/opt/keycloak/bin/kc.sh", "start", "--optimized", "--import-realm", "--http-enabled=true", "--http-host=127.0.0.1", "--http-port=8080", "--spi-theme--static-max-age=-1"],
      env: {
        KC_HOSTNAME: publicOrigin("login"),
        KC_TRUSTSTORE_PATHS: "/bundle-ca/ca.crt",
        // realm の設定（services/insurer-login/realm/insurer.json）が読む値
        NAMESPACE: ns,
        TRUST_DOMAIN,
        AUTH_ISSUER: ISSUER,
        APP_ORIGIN: CUSTOMER_ORIGIN,
        AUDIT_ORIGIN: publicOrigin("audit"),
      },
      memory: { requests: "512Mi", limits: "1Gi" },
      bundleCa: true,
    },
  },
];

/**
 * 確かめの役。乗っ取られた複製は、そのサービスの ServiceAccount で動く。顧客の役は、証明書を使わずに呼ぶ。
 * SPIRE の agent は、同じノードで同じ SPIFFE ID の Pod に、同じ SVID を配る（F-G53）。別の SVID を持たせるため、
 * mcp-2 は mcp-1 と別のノードに置く。
 */
export const PROBES = [
  { name: "probe-sales-agent", sa: "sales-agent" },
  { name: "probe-mcp-1", sa: "insurer-mcp" },
  { name: "probe-mcp-2", sa: "insurer-mcp", awayFrom: "probe-mcp-1" },
  { name: "probe-intruder", sa: "intruder" },
  { name: "probe-operator", sa: "operator" },
  { name: "probe-auditor", sa: "auditor" },
  // 顧客のアプリの BFF の役。顧客のアプリと同じ身元で、ログインサーバーにクライアント認証して A を受け取る（D-41）
  { name: "probe-customer-app", sa: "customer-app", jwtSvid: true },
];

export const SERVICE_ACCOUNTS = [
  "insurer-auth",
  "insurer-login",
  "sales-agent",
  "insurer-mcp",
  "insurer-backend",
  "customer-app",
  "insurer-audit",
  "entrance",
  "intruder",
  "operator",
  "auditor",
];
