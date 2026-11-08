import { CUSTOMER_ORIGIN, ENTRANCE, IMAGES, publicHost, type PublicName } from "./common.ts";
import { SPIRE_AGENT_CLUSTER, hcm, listener, upstream } from "./envoy.ts";
import { SOCKET_MOUNT, SOCKET_VOLUME, deployment, meta } from "./kubernetes.ts";

// ---- クラスタの入口（D-25） ----------------------------------------------------
// ブラウザからの要求を、名前（Host）で振り分ける。入口から先は、相手の SPIFFE ID を確かめる TLS で、証明書は示さない
// （顧客と同じく、証明書を持たない者として呼ぶ。F-G59）。

/**
 * 認可サーバーのうち、ブラウザに出す経路。passkey の登録はログインサーバーの画面で行い、受信箱は顧客のアプリの BFF が内部の経路で登録するので、
 * 今は出す経路がない（D-42）。トークンの要求、運用（/admin）、内部（/internal）、有効性の問い合わせ、連絡先（/contacts）は出さない。
 */
export const AUTH_PUBLIC_PATHS: string[] = [];

/** ログインサーバーのうち、ブラウザに出す経路。管理の画面と API、利用者の画面（account）は出さない。 */
export const LOGIN_PUBLIC_PATHS = ["/realms/insurer/protocol/openid-connect/", "/realms/insurer/login-actions/", "/realms/insurer/.well-known/", "/resources/"];

export const CORS = "envoy.filters.http.cors";

/** 顧客のアプリの画面（app の origin）からだけ、別の名前を呼ばせる。 */
export const corsFor = (credentials: boolean) => ({
  [CORS]: {
    "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
    allow_origin_string_match: [{ exact: CUSTOMER_ORIGIN }],
    allow_methods: "GET, POST, OPTIONS",
    allow_headers: "authorization, dpop, content-type",
    allow_credentials: credentials,
    max_age: "600",
  },
});

export const NOT_FOUND = { direct_response: { status: 404, body: { inline_string: "not found" } } };

export function entranceConfig() {
  const domains = (name: PublicName) => [publicHost(name), `${publicHost(name)}:${ENTRANCE.port}`];
  // 認可サーバーは、転送のヘッダーで、ブラウザが呼んだ URL を知る（DPoP の htu、戻り先）
  const forwarded = [
    { header: { key: "x-forwarded-proto", value: "http" }, append_action: "OVERWRITE_IF_EXISTS_OR_ADD" },
    { header: { key: "x-forwarded-port", value: String(ENTRANCE.port) }, append_action: "OVERWRITE_IF_EXISTS_OR_ADD" },
  ];
  const virtualHosts = [
    {
      name: "app",
      domains: domains("app"),
      routes: [
        // 直送の受け口は、保険会社のシステムからの mTLS の受け口だけで受ける
        { match: { prefix: "/notices" }, ...NOT_FOUND },
        // AG-UI の応答は、営業 AI エージェントの番が終わるまで続く。既定の 15 秒で切らない（BFF の出口と同じ 120 秒。D-41）
        { match: { path: "/bff/agui" }, route: { cluster: "to_customer_app", timeout: "120s" } },
        { match: { prefix: "/" }, route: { cluster: "to_customer_app" } },
      ],
    },
    {
      name: "login",
      domains: domains("login"),
      typed_per_filter_config: corsFor(false),
      routes: [
        ...LOGIN_PUBLIC_PATHS.map((prefix) => ({ match: { prefix }, route: { cluster: "to_insurer_login" } })),
        { match: { prefix: "/" }, ...NOT_FOUND },
      ],
    },
    {
      name: "auth",
      domains: domains("auth"),
      typed_per_filter_config: corsFor(false),
      request_headers_to_add: forwarded,
      routes: [
        ...AUTH_PUBLIC_PATHS.map((prefix) => ({ match: { prefix }, route: { cluster: "to_insurer_auth" } })),
        { match: { prefix: "/" }, ...NOT_FOUND },
      ],
    },
    {
      // 監査の担当の画面。戻り先を、ブラウザが呼んだ名前で作れるよう、転送のヘッダーを付ける
      name: "audit",
      domains: domains("audit"),
      request_headers_to_add: forwarded,
      routes: [{ match: { prefix: "/" }, route: { cluster: "to_insurer_audit", timeout: "60s" } }],
    },
  ];
  const corsFilter = { name: CORS, typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors" } };
  return {
    node: { id: "entrance", cluster: "entrance" },
    admin: { address: { socket_address: { address: "127.0.0.1", port_value: 9901 } } },
    static_resources: {
      listeners: [
        listener("entrance", "0.0.0.0", ENTRANCE.listen, {
          filters: [
            hcm(
              "entrance",
              { name: "entrance", virtual_hosts: virtualHosts, request_headers_to_remove: ["x-forwarded-client-cert", "x-forwarded-host"] },
              [corsFilter],
              { use_remote_address: true },
            ),
          ],
        }),
      ],
      clusters: [
        SPIRE_AGENT_CLUSTER,
        upstream("to_customer_app", "customer-app", 8443, false),
        upstream("to_insurer_auth", "insurer-auth", 8443, false),
        upstream("to_insurer_login", "insurer-login", 8443, false),
        upstream("to_insurer_audit", "insurer-audit", 8443, false),
      ],
    },
  };
}

export function entranceWorkload() {
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta("entrance-envoy"), data: { "envoy.json": JSON.stringify(entranceConfig()) } },
    {
      apiVersion: "v1",
      kind: "Service",
      metadata: meta("entrance"),
      spec: {
        type: "NodePort",
        selector: { app: "entrance" },
        ports: [{ name: "http", port: ENTRANCE.listen, targetPort: ENTRANCE.listen, nodePort: ENTRANCE.nodePort }],
      },
    },
    deployment("entrance", "entrance", { app: "entrance" }, {
      containers: [
        {
          name: "envoy",
          image: IMAGES.envoy,
          args: ["-c", "/etc/envoy/envoy.json", "--log-level", "warn"],
          ports: [{ containerPort: ENTRANCE.listen }],
          volumeMounts: [SOCKET_MOUNT, { name: "envoy", mountPath: "/etc/envoy" }],
        },
      ],
      volumes: [SOCKET_VOLUME, { name: "envoy", configMap: { name: "entrance-envoy" } }],
    }),
  ];
}
