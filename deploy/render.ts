// 名前空間ごとのマニフェストを組み立て、JSON の List で標準出力に書く（kubectl apply -f - で使う）。
// 使い方: node deploy/render.ts <secure|vulnerable>
// secure は良い実装だけで動き、vulnerable は防御を 1 つずつ外せる（D-20）。構成は同じである。

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const TRUST_DOMAIN = "gekko11.internal";
const ns = process.argv[2];
if (ns !== "secure" && ns !== "vulnerable") throw new Error("名前空間は secure か vulnerable");
const vulnerable = ns === "vulnerable";

const IMAGES = {
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

const spiffeId = (sa: string) => `spiffe://${TRUST_DOMAIN}/ns/${ns}/sa/${sa}`;
const host = (service: string) => `${service}.${ns}.svc`;

/**
 * クラスタの入口（D-25）。ブラウザは、名前空間ごとのポートで、app、login、auth、agent、audit の名前に届く。
 * 入口の名前は、ここだけで決める。RP ID、origin、issuer、戻り先、CORS は、ここから作る。
 */
const ENTRANCE = { domain: "localhost", port: vulnerable ? 8082 : 8081, nodePort: vulnerable ? 30082 : 30081, listen: 8080 };
type PublicName = "app" | "login" | "auth" | "agent" | "audit";
const publicHost = (name: PublicName) => `${name}.${ns}.${ENTRANCE.domain}`;
const publicOrigin = (name: PublicName) => `http://${publicHost(name)}:${ENTRANCE.port}`;
/** 認可サーバーの iss（B と C）。 */
const ISSUER = publicOrigin("auth");
/** ログインサーバーの iss（A、P、ID トークン。D-35）。 */
const LOGIN_ISSUER = `${publicOrigin("login")}/realms/insurer`;
/** ログインサーバーの公開鍵を、Envoy の出口から取るポートとパス。 */
const LOGIN_EGRESS = 15105;
const LOGIN_JWKS_URL = `http://127.0.0.1:${LOGIN_EGRESS}/realms/insurer/protocol/openid-connect/certs`;
const AUTH_JWKS_URL = "http://127.0.0.1:15101/oauth2/jwks";
const CUSTOMER_ORIGIN = publicOrigin("app");
/** passkey の RP ID と、署名した画面の origin（顧客のアプリ）。 */
const WEBAUTHN = { RP_ID: publicHost("app"), WEBAUTHN_ORIGINS: CUSTOMER_ORIGIN };

/** 防御を外す管理のポート（vulnerable だけ）。token-guard と、アプリ。 */
const ADMIN = { tokenGuard: 9090, app: 9091 };

type Name = "sales-agent" | "insurer-mcp" | "insurer-backend" | "customer-app" | "insurer-audit" | "insurer-login";

interface Egress {
  port: number;
  target: Name | "insurer-auth";
  /** token-guard が、受け口で確かめたトークンを、次の段のトークンに替えて付ける。 */
  exchange?: boolean;
}

interface Service {
  name: Name;
  /** 受け口: dpop は顧客（証明書なし）から、mtls はサービスから、open はトークンなしで相手の SPIFFE ID を見る。 */
  ingress: "dpop" | "mtls" | "open";
  port: number;
  /** トークンを見ない受け口で、サービスから mTLS で受けるポート（顧客のアプリの直送の受け口）。 */
  mtlsPort?: number;
  /** 呼んでよい相手（D27、NetworkPolicy）。probe は、確かめのために全てを呼べる。 */
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
    /** JWT-SVID をファイルで受け取る（監査サービス。D-38）。 */
    jwtSvid?: boolean;
    /** SPIRE の bundle の受け口の証明書を信頼する（ログインサーバー。D-38）。 */
    bundleCa?: boolean;
  };
}

/** vulnerable だけ: D29 を外すと、もう一方の発行者の公開鍵も使う。 */
const anyIssuerEgress: Egress[] = vulnerable ? [{ port: LOGIN_EGRESS, target: "insurer-login" }] : [];

/** 2 章の経路（architecture の 2-1）。 */
const SERVICES: Service[] = [
  {
    name: "sales-agent",
    ingress: "dpop",
    port: 8443,
    callers: [],
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
    // 提示の公開鍵を、保険会社のシステムから取り、画面に渡す（4-5）
    egress: [{ port: 15104, target: "insurer-backend" }],
    app: {
      image: IMAGES.node,
      command: ["node", "packages/customer-app/src/server.ts"],
      env: { NAMESPACE: ns, TRUST_DOMAIN, ISSUER: LOGIN_ISSUER, AUTH_ORIGIN: publicOrigin("auth"), RP_ID: WEBAUTHN.RP_ID, APP_ORIGIN: CUSTOMER_ORIGIN, AGENT_ORIGIN: publicOrigin("agent"), APP_ADMIN_PORT: String(ADMIN.app) },
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
    callers: ["sales-agent", "insurer-audit", "insurer-auth", ...(vulnerable ? ["insurer-mcp", "insurer-backend"] : [])],
    egress: [],
    app: {
      image: IMAGES.login,
      command: ["/opt/keycloak/bin/kc.sh", "start", "--optimized", "--import-realm", "--http-enabled=true", "--http-host=127.0.0.1", "--http-port=8080"],
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
const PROBES = [
  { name: "probe-sales-agent", sa: "sales-agent" },
  { name: "probe-mcp-1", sa: "insurer-mcp" },
  { name: "probe-mcp-2", sa: "insurer-mcp", awayFrom: "probe-mcp-1" },
  { name: "probe-intruder", sa: "intruder" },
  { name: "probe-operator", sa: "operator" },
  { name: "probe-auditor", sa: "auditor" },
];

const SERVICE_ACCOUNTS = [
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

// ---- Envoy ----------------------------------------------------------------

const sds = (name: string) => ({
  name,
  sds_config: {
    resource_api_version: "V3",
    api_config_source: {
      api_type: "GRPC",
      transport_api_version: "V3",
      grpc_services: [{ envoy_grpc: { cluster_name: "spire_agent" } }],
    },
  },
});

const local = (name: string, port: number) => ({
  name,
  type: "STATIC",
  load_assignment: {
    cluster_name: name,
    endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: "127.0.0.1", port_value: port } } } }] }],
  },
});

/** サービスどうしが mTLS で呼ぶポート。 */
const portOf = (target: Egress["target"]) => (target === "insurer-auth" || target === "insurer-login" || target === "sales-agent" ? 8443 : 9443);

/**
 * 相手の SPIFFE ID を確かめて、SVID で mTLS をかける上流。
 * 接続は要求ごとにつなぎ直し、そのときの SVID で示す。使い回すと、SVID が入れ替わった後も前の証明書で示し続け、
 * 新しい証明書に結んだトークンと食い違う（F-G54）。
 */
const upstream = (name: string, service: string, port: number, presentSvid = true) => ({
  name,
  type: "STRICT_DNS",
  connect_timeout: "5s",
  typed_extension_protocol_options: {
    "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
      "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
      common_http_protocol_options: { max_requests_per_connection: 1 },
      explicit_http_config: { http_protocol_options: {} },
    },
  },
  load_assignment: {
    cluster_name: name,
    endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: `${host(service)}.cluster.local`, port_value: port } } } }] }],
  },
  transport_socket: {
    name: "envoy.transport_sockets.tls",
    typed_config: {
      "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
      common_tls_context: {
        ...(presentSvid ? { tls_certificate_sds_secret_configs: [sds("default")] } : {}),
        combined_validation_context: {
          default_validation_context: {
            match_typed_subject_alt_names: [{ san_type: "URI", matcher: { exact: spiffeId(service) } }],
          },
          validation_context_sds_secret_config: sds("ROOTCA"),
        },
      },
    },
  },
});

const EXT_AUTHZ = "envoy.filters.http.ext_authz";

const extAuthz = (pathPrefix: string, requestHeaders: string[], upstreamHeaders: object[]) => ({
  name: EXT_AUTHZ,
  typed_config: {
    "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
    transport_api_version: "V3",
    failure_mode_allow: false,
    http_service: {
      server_uri: { uri: "http://127.0.0.1:9100", cluster: "token_guard", timeout: "10s" },
      path_prefix: pathPrefix,
      authorization_response: { allowed_upstream_headers: { patterns: upstreamHeaders } },
    },
    allowed_headers: { patterns: requestHeaders.map((exact) => ({ exact })) },
  },
});

const NO_AUTHZ = {
  [EXT_AUTHZ]: { "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute", disabled: true },
};

const ROUTER = {
  name: "envoy.filters.http.router",
  typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router" },
};

/** アクセスログ。パスにトークンが入っていないことを確かめるのに使う（D24）。 */
const ACCESS_LOG = [
  {
    name: "envoy.access_loggers.stdout",
    typed_config: {
      "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
      log_format: {
        json_format: { at: "%START_TIME%", method: "%REQ(:METHOD)%", path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%", status: "%RESPONSE_CODE%", peer: "%DOWNSTREAM_PEER_URI_SAN%" },
      },
    },
  },
];

const SPIRE_AGENT_CLUSTER = {
  name: "spire_agent",
  type: "STATIC",
  connect_timeout: "1s",
  typed_extension_protocol_options: {
    "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
      "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
      explicit_http_config: { http2_protocol_options: {} },
    },
  },
  load_assignment: {
    cluster_name: "spire_agent",
    endpoints: [{ lb_endpoints: [{ endpoint: { address: { pipe: { path: "/run/spire/sockets/agent.sock" } } } }] }],
  },
};

const hcm = (stat: string, routeConfig: object, filters: object[], extra: object = {}) => ({
  name: "envoy.filters.network.http_connection_manager",
  typed_config: {
    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
    stat_prefix: stat,
    route_config: routeConfig,
    http_filters: [...filters, ROUTER],
    access_log: ACCESS_LOG,
    ...extra,
  },
});

const listener = (name: string, address: string, port: number, filterChain: object) => ({
  name,
  address: { socket_address: { address, port_value: port } },
  filter_chains: [filterChain],
});

function envoyConfig(s: Service) {
  const guarded = s.ingress !== "open";
  // アプリは、トークンも証明書も受け取らない（2-2）。トークンを見ない経路だけ、相手の証明書の情報を渡す
  const routes = [
    ...(s.openPaths ?? []).map((prefix) => ({
      match: { prefix },
      route: { cluster: "app" },
      request_headers_to_remove: ["authorization", "dpop"],
      typed_per_filter_config: NO_AUTHZ,
    })),
    {
      match: { prefix: "/" },
      route: { cluster: "app", timeout: "120s" },
      // ログインサーバーは、トークンの要求の DPoP の proof を自分で確かめる
      request_headers_to_remove: guarded ? ["authorization", "dpop", "x-forwarded-client-cert"] : s.name === "insurer-login" ? [] : ["authorization", "dpop"],
    },
  ];
  // 証明書を求める受け口だけ、検証の設定を入れる。入れると、Envoy は証明書のない相手（顧客）を拒む
  const inbound = (name: string, port: number, mtls: boolean) =>
    listener(name, "0.0.0.0", port, {
      transport_socket: {
        name: "envoy.transport_sockets.tls",
        typed_config: {
          "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
          require_client_certificate: mtls,
          common_tls_context: {
            tls_certificate_sds_secret_configs: [sds("default")],
            ...(mtls ? { validation_context_sds_secret_config: sds("ROOTCA") } : {}),
          },
        },
      },
      filters: [
        hcm(
          name,
          { name, virtual_hosts: [{ name: "app", domains: ["*"], routes }] },
          guarded ? [extAuthz("/ingress", ["authorization", "dpop", "x-forwarded-client-cert"], [{ prefix: "x-auth-" }])] : [],
          { forward_client_cert_details: "SANITIZE_SET", set_current_client_cert_details: { uri: true } },
        ),
      ],
    });
  const ingress = inbound("ingress", s.port, s.ingress === "mtls");
  const listeners: object[] = [ingress, ...(s.mtlsPort ? [inbound("ingress_mtls", s.mtlsPort, true)] : [])];
  const clusters: object[] = [
    SPIRE_AGENT_CLUSTER,
    local("app", 8080),
    local("token_guard", 9100),
  ];

  for (const e of s.egress) {
    const cluster = `to_${e.target.replace(/-/g, "_")}`;
    listeners.push(
      listener(`egress-${e.target}`, "127.0.0.1", e.port, {
        filters: [
          hcm(
            `egress_${e.port}`,
            {
              name: `egress_${e.port}`,
              virtual_hosts: [
                {
                  name: e.target,
                  domains: ["*"],
                  routes: [{ match: { prefix: "/" }, route: { cluster, host_rewrite_literal: `${host(e.target)}:${portOf(e.target)}`, timeout: "120s" } }],
                },
              ],
              request_headers_to_remove: ["x-auth-ctx"],
            },
            // 出口では、受け口で確かめたトークンの控えを、次の段のトークンに替えて付ける
            e.exchange ? [extAuthz("/egress", ["x-auth-ctx"], [{ exact: "authorization" }])] : [],
          ),
        ],
      }),
    );
    clusters.push(upstream(cluster, e.target, portOf(e.target)));
  }

  return {
    node: { id: s.name, cluster: s.name },
    admin: { address: { socket_address: { address: "127.0.0.1", port_value: 9901 } } },
    static_resources: { listeners, clusters },
  };
}

// ---- Kubernetes -----------------------------------------------------------

const meta = (name: string, labels: Record<string, string> = {}) => ({ name, namespace: ns, labels });

const SOCKET_VOLUME = { name: "spire-agent-socket", hostPath: { path: "/run/spire/sockets", type: "Directory" } };
const SOCKET_MOUNT = { name: "spire-agent-socket", mountPath: "/run/spire/sockets", readOnly: true };
const SVID_VOLUME = { name: "svid", emptyDir: {} };
const SVID_MOUNT = { name: "svid", mountPath: "/svid" };

/** SVID をファイルに書き出し、入れ替える（native sidecar）。 */
const HELPER_CONFIG = `agent_address = "/run/spire/sockets/agent.sock"
cert_dir = "/svid"
daemon_mode = true
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
`;
const helperSidecar = {
  name: "spiffe-helper",
  image: IMAGES.helper,
  restartPolicy: "Always",
  args: ["-config", "/config/helper.conf"],
  volumeMounts: [SOCKET_MOUNT, SVID_MOUNT, { name: "helper-config", mountPath: "/config" }],
};
/** 監査サービスの分。ログインサーバーの発行者を宛先にした JWT-SVID も、ファイルに書き出す（D-38）。 */
const HELPER_JWT_CONFIG = `${HELPER_CONFIG}jwt_svids = [{jwt_audience="${LOGIN_ISSUER}", jwt_svid_file_name="jwt_svid.token"}]
`;
const HELPER_CONFIG_VOLUME = { name: "helper-config", configMap: { name: "spiffe-helper" } };
const waitForSvid = (cmd: string) => ["sh", "-c", `until [ -s /svid/svid_bundle.pem ]; do sleep 1; done; exec ${cmd}`];

/** ポートが開いたら準備ができたとみなす。kubelet からの通信は NetworkPolicy で拒むので、コンテナーの中で確かめる。 */
const ready = (port: number) => ({
  readinessProbe: {
    exec: { command: ["bash", "-c", `exec 3<>/dev/tcp/127.0.0.1/${port}`] },
    periodSeconds: 3,
    failureThreshold: 60,
  },
});

const POD_SECURITY = { runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, runAsNonRoot: true };

const env = (vars: Record<string, string | undefined>) =>
  Object.entries(vars)
    .filter((e): e is [string, string] => e[1] !== undefined)
    .map(([name, value]) => ({ name, value }));

function deployment(name: string, sa: string, labels: Record<string, string>, spec: object) {
  return {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: meta(name, labels),
    spec: {
      replicas: 1,
      selector: { matchLabels: { name } },
      template: { metadata: { labels: { ...labels, name } }, spec: { serviceAccountName: sa, securityContext: POD_SECURITY, ...spec } },
    },
  };
}

const service = (name: string, ...ports: number[]) => ({
  apiVersion: "v1",
  kind: "Service",
  metadata: meta(name),
  spec: {
    selector: { app: name },
    // 監査サービスには、防御を外す受け口がない
    ports: [...ports, ...(vulnerable && name !== "insurer-audit" ? [ADMIN.tokenGuard, ADMIN.app] : [])].map((port) => ({ name: `p${port}`, port, targetPort: port })),
  },
});

function serviceWorkload(s: Service) {
  const next = s.egress.find((e) => e.exchange)?.target;
  const containers: object[] = [
    {
      name: "envoy",
      image: IMAGES.envoy,
      args: ["-c", "/etc/envoy/envoy.json", "--log-level", "warn"],
      ports: [{ containerPort: s.port }],
      volumeMounts: [SOCKET_MOUNT, { name: "envoy", mountPath: "/etc/envoy" }],
    },
  ];
  if (s.ingress !== "open") {
    containers.push({
      name: "token-guard",
      image: IMAGES.node,
      command: ["node", "packages/token-guard/src/server.ts"],
      env: env({
        SERVICE: s.name,
        NAMESPACE: ns,
        ISSUER: s.ingress === "dpop" ? LOGIN_ISSUER : ISSUER,
        JWKS_URL: s.ingress === "dpop" ? LOGIN_JWKS_URL : AUTH_JWKS_URL,
        OTHER_JWKS_URL: vulnerable && s.ingress === "mtls" ? LOGIN_JWKS_URL : undefined,
        INGRESS_PROOF: s.ingress,
        PUBLIC_ORIGIN: s.ingress === "dpop" ? publicOrigin("agent") : undefined,
        ALLOWED_CALLERS: s.callers.join(","),
        NEXT_SERVICE: next,
        TOKEN_GUARD_ADMIN_PORT: String(ADMIN.tokenGuard),
      }),
    });
  }
  containers.push({
    name: "app",
    image: s.app.image,
    command: s.app.command,
    env: [
      ...env({ APP_PORT: "8080", ...s.app.env }),
      // 営業 AI エージェントの Claude の認証情報は、secure の名前空間にだけ置く（D-23）
      ...(s.name === "sales-agent" && !vulnerable
        ? [{ name: "CLAUDE_CODE_OAUTH_TOKEN", valueFrom: { secretKeyRef: { name: "claude", key: "token", optional: true } } }]
        : []),
    ],
    ...(s.app.memory || s.app.command[0] === "java"
      ? { resources: { requests: { memory: s.app.memory?.requests ?? "256Mi" }, limits: { memory: s.app.memory?.limits ?? "512Mi" } }, ...ready(8080) }
      : {}),
    volumeMounts: [...(s.app.jwtSvid ? [SVID_MOUNT] : []), ...(s.app.bundleCa ? [{ name: "bundle-ca", mountPath: "/bundle-ca", readOnly: true }] : [])],
  });
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta(`${s.name}-envoy`), data: { "envoy.json": JSON.stringify(envoyConfig(s)) } },
    service(s.name, s.port, ...(s.mtlsPort ? [s.mtlsPort] : [])),
    deployment(s.name, s.name, { app: s.name }, {
      // 監査サービスは、ログインサーバーへのクライアント認証に、JWT-SVID を使う（D-38）
      ...(s.app.jwtSvid ? { initContainers: [helperSidecar] } : {}),
      containers,
      volumes: [
        SOCKET_VOLUME,
        { name: "envoy", configMap: { name: `${s.name}-envoy` } },
        ...(s.app.jwtSvid ? [SVID_VOLUME, { name: "helper-config", configMap: { name: "spiffe-helper-jwt" } }] : []),
        ...(s.app.bundleCa ? [{ name: "bundle-ca", configMap: { name: "spire-bundle-ca" } }] : []),
      ],
    }),
  ];
}

/** 認可サーバーの出口だけの Envoy。ログインサーバーの公開鍵を、相手の SPIFFE ID を確かめて取る（D-36）。 */
function authEgressConfig() {
  const cluster = "to_insurer_login";
  return {
    node: { id: "insurer-auth", cluster: "insurer-auth" },
    admin: { address: { socket_address: { address: "127.0.0.1", port_value: 9901 } } },
    static_resources: {
      listeners: [
        listener("egress-insurer-login", "127.0.0.1", LOGIN_EGRESS, {
          filters: [
            hcm(`egress_${LOGIN_EGRESS}`, {
              name: `egress_${LOGIN_EGRESS}`,
              virtual_hosts: [
                { name: "insurer-login", domains: ["*"], routes: [{ match: { prefix: "/" }, route: { cluster, host_rewrite_literal: `${host("insurer-login")}:8443` } }] },
              ],
            }, []),
          ],
        }),
      ],
      clusters: [SPIRE_AGENT_CLUSTER, upstream(cluster, "insurer-login", 8443)],
    },
  };
}

function authWorkload() {
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta("insurer-auth-envoy"), data: { "envoy.json": JSON.stringify(authEgressConfig()) } },
    service("insurer-auth", 8443),
    deployment("insurer-auth", "insurer-auth", { app: "insurer-auth" }, {
      initContainers: [helperSidecar],
      containers: [
        {
          name: "insurer-auth",
          image: IMAGES.auth,
          command: waitForSvid("java -jar /app/insurer-auth.jar"),
          env: env({
            SPRING_PROFILES_ACTIVE: "k8s",
            SVID_DIR: "/svid",
            ISSUER,
            NAMESPACE: ns,
            TRUST_DOMAIN,
            LOGIN_ISSUER,
            LOGIN_JWKS_URL,
            ...WEBAUTHN,
          }),
          ports: [{ containerPort: 8443 }],
          resources: { requests: { memory: "256Mi" }, limits: { memory: "512Mi" } },
          ...ready(8443),
          volumeMounts: [SVID_MOUNT],
        },
        {
          name: "envoy",
          image: IMAGES.envoy,
          args: ["-c", "/etc/envoy/envoy.json", "--log-level", "warn"],
          volumeMounts: [SOCKET_MOUNT, { name: "envoy", mountPath: "/etc/envoy" }],
        },
      ],
      volumes: [SOCKET_VOLUME, SVID_VOLUME, HELPER_CONFIG_VOLUME, { name: "envoy", configMap: { name: "insurer-auth-envoy" } }],
    }),
  ];
}

// ---- クラスタの入口（D-25） ----------------------------------------------------
// ブラウザからの要求を、名前（Host）で振り分ける。入口から先は、相手の SPIFFE ID を確かめる TLS で、証明書は示さない
// （顧客と同じく、証明書を持たない者として呼ぶ。F-G59）。

/** 認可サーバーのうち、ブラウザに出す経路。トークンの要求、運用（/admin）、内部（/internal）、有効性の問い合わせは出さない。 */
const AUTH_PUBLIC_PATHS = ["/passkeys/register/", "/passkeys/mine"];

/** ログインサーバーのうち、ブラウザに出す経路。管理の画面と API、利用者の画面（account）は出さない。 */
const LOGIN_PUBLIC_PATHS = ["/realms/insurer/protocol/openid-connect/", "/realms/insurer/login-actions/", "/realms/insurer/.well-known/", "/resources/"];

const CORS = "envoy.filters.http.cors";

/** 顧客のアプリの画面（app の origin）からだけ、別の名前を呼ばせる。 */
const corsFor = (credentials: boolean) => ({
  [CORS]: {
    "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
    allow_origin_string_match: [{ exact: CUSTOMER_ORIGIN }],
    allow_methods: "GET, POST, OPTIONS",
    allow_headers: "authorization, dpop, content-type",
    allow_credentials: credentials,
    max_age: "600",
  },
});

const NOT_FOUND = { direct_response: { status: 404, body: { inline_string: "not found" } } };

function entranceConfig() {
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
      name: "agent",
      domains: domains("agent"),
      typed_per_filter_config: corsFor(false),
      routes: [{ match: { prefix: "/" }, route: { cluster: "to_sales_agent", timeout: "120s" } }],
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
        upstream("to_sales_agent", "sales-agent", 8443, false),
        upstream("to_insurer_audit", "insurer-audit", 8443, false),
      ],
    },
  };
}

function entranceWorkload() {
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

// ---- 記録の集約（D-30） -------------------------------------------------------
// 名前空間ごとに Loki を 1 つ置く。記録を届けるのは logging の名前空間の Alloy だけで、読むのは監査サービスだけである。

/** 単一のプロセスで、ファイルに保存する。保存期間は 7 日（compactor の retention）。 */
const LOKI_CONFIG = `auth_enabled: false
server:
  http_listen_port: 3100
  grpc_listen_port: 9096
  log_level: warn
common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
limits_config:
  retention_period: 168h
compactor:
  working_directory: /loki/compactor
  retention_enabled: true
  delete_request_store: filesystem
analytics:
  reporting_enabled: false
`;

function lokiWorkload() {
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta("loki-config"), data: { "loki.yaml": LOKI_CONFIG } },
    { apiVersion: "v1", kind: "Service", metadata: meta("loki"), spec: { selector: { app: "loki" }, ports: [{ name: "http", port: 3100, targetPort: 3100 }] } },
    deployment("loki", "default", { app: "loki" }, {
      containers: [
        {
          name: "loki",
          image: IMAGES.loki,
          args: ["-config.file=/etc/loki/loki.yaml"],
          ports: [{ containerPort: 3100 }],
          resources: { requests: { memory: "128Mi" }, limits: { memory: "384Mi" } },
          volumeMounts: [{ name: "config", mountPath: "/etc/loki" }, { name: "data", mountPath: "/loki" }],
        },
      ],
      volumes: [{ name: "config", configMap: { name: "loki-config" } }, { name: "data", emptyDir: {} }],
    }),
  ];
}

const probe = (p: (typeof PROBES)[number]) =>
  deployment(p.name, p.sa, { app: "probe" }, {
    ...("awayFrom" in p
      ? {
          affinity: {
            podAntiAffinity: {
              requiredDuringSchedulingIgnoredDuringExecution: [
                { labelSelector: { matchLabels: { name: p.awayFrom } }, topologyKey: "kubernetes.io/hostname" },
              ],
            },
          },
        }
      : {}),
    initContainers: [helperSidecar],
    containers: [
      {
        name: "probe",
        image: IMAGES.node,
        command: waitForSvid("sleep infinity"),
        env: env({ NAMESPACE: ns, SERVICE_ACCOUNT: p.sa }),
        volumeMounts: [SVID_MOUNT],
      },
    ],
    volumes: [SOCKET_VOLUME, SVID_VOLUME, HELPER_CONFIG_VOLUME],
  });

// ---- NetworkPolicy: 全て拒否から始め、2 章の経路だけを許す。名前空間をまたぐ通信は許さない ----

const policy = (name: string, spec: object) => ({
  apiVersion: "networking.k8s.io/v1",
  kind: "NetworkPolicy",
  metadata: meta(name),
  spec,
});
const from = (...apps: string[]) => apps.map((app) => ({ podSelector: { matchLabels: { app } } }));
const allow = (app: string, ports: number[], callers: string[], suffix = "") => [
  policy(`${app}-ingress${suffix}`, {
    podSelector: { matchLabels: { app } },
    policyTypes: ["Ingress"],
    ingress: [{ from: from(...callers), ports: ports.map((port) => ({ port })) }],
  }),
  ...callers.map((caller) =>
    policy(`${caller}-to-${app}${suffix}`, {
      podSelector: { matchLabels: { app: caller } },
      policyTypes: ["Egress"],
      egress: [{ to: from(app), ports: ports.map((port) => ({ port })) }],
    }),
  ),
];

const PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

const networkPolicies = [
  policy("default-deny", { podSelector: {}, policyTypes: ["Ingress", "Egress"] }),
  policy("allow-dns", {
    podSelector: {},
    policyTypes: ["Egress"],
    egress: [
      {
        to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } }, podSelector: { matchLabels: { "k8s-app": "kube-dns" } } }],
        ports: [{ port: 53, protocol: "UDP" }, { port: 53, protocol: "TCP" }],
      },
    ],
  }),
  // 保険会社のシステムは、トークンを確かめる公開鍵と passkey の公開鍵を、認可サーバーから取る
  ...allow("insurer-auth", [8443], ["sales-agent", "insurer-mcp", "insurer-backend", "probe"]),
  // ログインサーバーは、JWT-SVID を確かめる公開鍵を、SPIRE の bundle の受け口から取る（D-38）
  policy("insurer-login-to-spire", {
    podSelector: { matchLabels: { app: "insurer-login" } },
    policyTypes: ["Egress"],
    egress: [{ to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "spire" } }, podSelector: { matchLabels: { app: "spire-server" } } }], ports: [{ port: 8443 }] }],
  }),
  ...SERVICES.flatMap((s) => allow(s.name, [s.port, ...(s.mtlsPort ? [s.mtlsPort] : [])], [...s.callers, "probe"])),
  // クラスタの入口: 外から入口へ。入口からは、ブラウザが使う 5 つの受け口へだけ
  policy("entrance-ingress", { podSelector: { matchLabels: { app: "entrance" } }, policyTypes: ["Ingress"], ingress: [{ ports: [{ port: ENTRANCE.listen }] }] }),
  ...["insurer-auth", "insurer-login", "sales-agent", "customer-app", "insurer-audit"].flatMap((app) => allow(app, [8443], ["entrance"], "-entrance")),
  ...allow("insurer-backend", [9443], ["customer-app"], "-offer-keys"),
  // 監査サービスは、保険会社のシステムの自己申告（/audit/records）を読む
  ...allow("insurer-backend", [9443], ["insurer-audit"], "-audit"),
  // クラスタの外へは、secure の営業 AI エージェントが、モデルの提供元を呼ぶ通信だけを許す（architecture の 2-3）
  ...(vulnerable
    ? []
    : [
        policy("sales-agent-to-model", {
          podSelector: { matchLabels: { app: "sales-agent" } },
          policyTypes: ["Egress"],
          egress: [{ to: [{ ipBlock: { cidr: "0.0.0.0/0", except: PRIVATE } }], ports: [{ port: 443 }] }],
        }),
      ]),
  // Loki: logging の名前空間の Alloy だけが届け、監査サービスだけが読む
  policy("loki-ingress", {
    podSelector: { matchLabels: { app: "loki" } },
    policyTypes: ["Ingress"],
    ingress: [
      {
        from: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "logging" } }, podSelector: { matchLabels: { app: "alloy" } } }],
        ports: [{ port: 3100 }],
      },
      { from: from("insurer-audit"), ports: [{ port: 3100 }] },
    ],
  }),
  policy("insurer-audit-to-loki", {
    podSelector: { matchLabels: { app: "insurer-audit" } },
    policyTypes: ["Egress"],
    egress: [{ to: from("loki"), ports: [{ port: 3100 }] }],
  }),
  // vulnerable だけ: 確かめの役が、防御を外す管理のポートを呼ぶ
  ...(vulnerable
    ? [...SERVICES.map((s) => s.name).filter((n) => n !== "insurer-audit"), "insurer-auth"].flatMap((app) => allow(app, [ADMIN.tokenGuard, ADMIN.app], ["probe"], "-admin"))
    : []),
];

const items = [
  { apiVersion: "v1", kind: "Namespace", metadata: { name: ns } },
  ...SERVICE_ACCOUNTS.map((sa) => ({ apiVersion: "v1", kind: "ServiceAccount", metadata: meta(sa) })),
  { apiVersion: "v1", kind: "ConfigMap", metadata: meta("spiffe-helper"), data: { "helper.conf": HELPER_CONFIG } },
  { apiVersion: "v1", kind: "ConfigMap", metadata: meta("spiffe-helper-jwt"), data: { "helper.conf": HELPER_JWT_CONFIG } },
  ...networkPolicies,
  ...authWorkload(),
  ...entranceWorkload(),
  ...lokiWorkload(),
  ...SERVICES.flatMap(serviceWorkload),
  ...PROBES.map(probe),
];

// ---- 変わったものだけを更新する ----
// タグは固定で、ConfigMap の変更も Pod に伝わらない（Envoy は設定を読み直さない）。そのままでは、中身を替えても更新が始まらない。
// そこで、イメージの中身と設定の内容のハッシュを Pod の定義に入れる。kubectl apply は、これが変わった Deployment だけを更新する。

/** イメージの中身。ID は、同じ中身でもビルドのたびに変わるので、レイヤーのハッシュを使う。 */
const imageId = (image: string) => {
  try {
    return execFileSync("docker", ["image", "inspect", "--format", "{{json .RootFS.Layers}}", image], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return image; // 手元にない外部のイメージは、版を固定したタグで決まる
  }
};

function stamp(item: any) {
  if (item.kind !== "Deployment") return item;
  const spec = item.spec.template.spec;
  const images = [...(spec.initContainers ?? []), ...spec.containers].map((c: { image: string }) => imageId(c.image));
  const configs = (spec.volumes ?? [])
    .flatMap((v: { configMap?: { name: string } }) => (v.configMap ? [v.configMap.name] : []))
    .map((name: string) => (items as any[]).find((i) => i.kind === "ConfigMap" && i.metadata.name === name)?.data);
  const revision = createHash("sha256").update(JSON.stringify({ images, configs })).digest("hex").slice(0, 16);
  item.spec.template.metadata.annotations = { "gekko11/revision": revision };
  return item;
}

console.log(JSON.stringify({ apiVersion: "v1", kind: "List", items: items.map(stamp) }, null, 2));
