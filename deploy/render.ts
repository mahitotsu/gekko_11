// 名前空間ごとのマニフェストを組み立て、JSON の List で標準出力に書く（kubectl apply -f - で使う）。
// 使い方: node deploy/render.ts <secure|vulnerable>
// secure は良い実装だけで動き、vulnerable は防御を 1 つずつ外せる（D-20）。構成は同じである。

const TRUST_DOMAIN = "gekko11.internal";
const ns = process.argv[2];
if (ns !== "secure" && ns !== "vulnerable") throw new Error("名前空間は secure か vulnerable");
const vulnerable = ns === "vulnerable";

const IMAGES = {
  envoy: "envoyproxy/envoy:v1.31.5",
  helper: "ghcr.io/spiffe/spiffe-helper:0.12.2",
  auth: `gekko11/insurer-auth:${ns}`,
  backend: `gekko11/insurer-backend:${ns}`,
  mcp: "gekko11/insurer-mcp:dev",
  node: `gekko11/node:${ns}`,
};

const spiffeId = (sa: string) => `spiffe://${TRUST_DOMAIN}/ns/${ns}/sa/${sa}`;
const host = (service: string) => `${service}.${ns}.svc`;
const ISSUER = `https://${host("insurer-auth")}:8443`;
const CUSTOMER_ORIGIN = `https://${host("customer-app")}:8443`;
/** passkey の RP ID と、署名した画面の origin（顧客のアプリ）。 */
const WEBAUTHN = { RP_ID: host("customer-app"), WEBAUTHN_ORIGINS: CUSTOMER_ORIGIN };

/** 防御を外す管理のポート（vulnerable だけ）。token-guard と、アプリ。 */
const ADMIN = { tokenGuard: 9090, app: 9091 };

type Name = "sales-agent" | "insurer-mcp" | "insurer-backend" | "customer-app";

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
  app: { image: string; command: string[]; env?: Record<string, string | undefined> };
}

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
    ],
    app: { image: IMAGES.mcp, command: ["python", "-m", "insurer_mcp.app"], env: { NAMESPACE: ns } },
  },
  {
    name: "insurer-backend",
    ingress: "mtls",
    port: 9443,
    callers: ["insurer-mcp"],
    openPaths: ["/audit/"],
    egress: [
      { port: 15101, target: "insurer-auth" },
      { port: 15103, target: "customer-app" },
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
    egress: [],
    app: { image: IMAGES.node, command: ["node", "packages/customer-app/src/server.ts"], env: { NAMESPACE: ns, TRUST_DOMAIN } },
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
  "sales-agent",
  "insurer-mcp",
  "insurer-backend",
  "customer-app",
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
const portOf = (target: Egress["target"]) => (target === "insurer-auth" || target === "sales-agent" ? 8443 : 9443);

/**
 * 相手の SPIFFE ID を確かめて、SVID で mTLS をかける上流。
 * 接続は要求ごとにつなぎ直し、そのときの SVID で示す。使い回すと、SVID が入れ替わった後も前の証明書で示し続け、
 * 新しい証明書に結んだトークンと食い違う（F-G54）。
 */
const upstream = (name: string, service: string, port: number) => ({
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
        tls_certificate_sds_secret_configs: [sds("default")],
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
      request_headers_to_remove: guarded ? ["authorization", "dpop", "x-forwarded-client-cert"] : ["authorization", "dpop"],
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
    {
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
    },
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
    ports: [...ports, ...(vulnerable ? [ADMIN.tokenGuard, ADMIN.app] : [])].map((port) => ({ name: `p${port}`, port, targetPort: port })),
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
        ISSUER,
        INGRESS_PROOF: s.ingress,
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
    ...(s.app.image === IMAGES.backend ? { resources: { requests: { memory: "256Mi" }, limits: { memory: "512Mi" } }, ...ready(8080) } : {}),
  });
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta(`${s.name}-envoy`), data: { "envoy.json": JSON.stringify(envoyConfig(s)) } },
    service(s.name, s.port, ...(s.mtlsPort ? [s.mtlsPort] : [])),
    deployment(s.name, s.name, { app: s.name }, {
      containers,
      volumes: [SOCKET_VOLUME, { name: "envoy", configMap: { name: `${s.name}-envoy` } }],
    }),
  ];
}

function authWorkload() {
  return [
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
            CUSTOMER_REDIRECT_URI: `${CUSTOMER_ORIGIN}/callback`,
            ...WEBAUTHN,
          }),
          ports: [{ containerPort: 8443 }],
          resources: { requests: { memory: "256Mi" }, limits: { memory: "512Mi" } },
          ...ready(8443),
          volumeMounts: [SVID_MOUNT],
        },
      ],
      volumes: [SOCKET_VOLUME, SVID_VOLUME, HELPER_CONFIG_VOLUME],
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
  ...SERVICES.flatMap((s) => allow(s.name, [s.port, ...(s.mtlsPort ? [s.mtlsPort] : [])], [...s.callers, "probe"])),
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
  // vulnerable だけ: 確かめの役が、防御を外す管理のポートを呼ぶ
  ...(vulnerable
    ? [...SERVICES.map((s) => s.name), "insurer-auth"].flatMap((app) => allow(app, [ADMIN.tokenGuard, ADMIN.app], ["probe"], "-admin"))
    : []),
];

const items = [
  { apiVersion: "v1", kind: "Namespace", metadata: { name: ns } },
  ...SERVICE_ACCOUNTS.map((sa) => ({ apiVersion: "v1", kind: "ServiceAccount", metadata: meta(sa) })),
  { apiVersion: "v1", kind: "ConfigMap", metadata: meta("spiffe-helper"), data: { "helper.conf": HELPER_CONFIG } },
  ...networkPolicies,
  ...authWorkload(),
  ...SERVICES.flatMap(serviceWorkload),
  ...PROBES.map(probe),
];

console.log(JSON.stringify({ apiVersion: "v1", kind: "List", items }, null, 2));
