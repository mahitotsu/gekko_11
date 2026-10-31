// 名前空間ごとのマニフェストを組み立て、JSON の List で標準出力に書く（kubectl apply -f - で使う）。
// 使い方: node deploy/render.ts <secure|vulnerable>
// secure は良い実装だけで動き、vulnerable は token-guard の防御を外せる（D-20）。構成は同じである。

const TRUST_DOMAIN = "gekko11.internal";
const ns = process.argv[2];
if (ns !== "secure" && ns !== "vulnerable") throw new Error("名前空間は secure か vulnerable");

const IMAGES = {
  envoy: "envoyproxy/envoy:v1.31.5",
  helper: "ghcr.io/spiffe/spiffe-helper:0.12.2",
  auth: "gekko11/insurer-auth:dev",
  node: `gekko11/node:${ns}`,
};
/** vulnerable で外す防御（scenarios の D26、D27）。 */
const DEFENSES_OFF = ns === "vulnerable" ? "D26,D27" : "";

const spiffeId = (sa: string) => `spiffe://${TRUST_DOMAIN}/ns/${ns}/sa/${sa}`;
const host = (service: string) => `${service}.${ns}.svc`;
const ISSUER = `https://${host("insurer-auth")}:8443`;

interface Service {
  name: "sales-agent" | "insurer-mcp" | "insurer-backend";
  /** 顧客のアプリからは DPoP、サービスからは mTLS で受ける。 */
  ingress: "dpop" | "mtls";
  port: number;
  callers: string[];
  next?: Service["name"];
}

/** 2 章の経路（architecture の 2-1）。 */
const SERVICES: Service[] = [
  { name: "sales-agent", ingress: "dpop", port: 8443, callers: [], next: "insurer-mcp" },
  { name: "insurer-mcp", ingress: "mtls", port: 9443, callers: ["sales-agent"], next: "insurer-backend" },
  { name: "insurer-backend", ingress: "mtls", port: 9443, callers: ["insurer-mcp"] },
];

/**
 * 確かめの役。乗っ取られた複製は、そのサービスの ServiceAccount で動く。
 * SPIRE の agent は、同じノードで同じ SPIFFE ID の Pod に、同じ SVID を配る。別の SVID を持たせるため、
 * mcp-2 は mcp-1 と別のノードに置く。
 */
const PROBES = [
  { name: "probe-sales-agent", sa: "sales-agent" },
  { name: "probe-mcp-1", sa: "insurer-mcp" },
  { name: "probe-mcp-2", sa: "insurer-mcp", awayFrom: "probe-mcp-1" },
  { name: "probe-intruder", sa: "intruder" },
];

const SERVICE_ACCOUNTS = ["insurer-auth", "sales-agent", "insurer-mcp", "insurer-backend", "intruder"];

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

/** 相手の SPIFFE ID を確かめて、SVID で mTLS をかける上流。 */
const upstream = (name: string, service: string, port: number) => ({
  name,
  type: "STRICT_DNS",
  connect_timeout: "5s",
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

const extAuthz = (pathPrefix: string, requestHeaders: string[], upstreamHeaders: object[]) => ({
  name: "envoy.filters.http.ext_authz",
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

const ROUTER = {
  name: "envoy.filters.http.router",
  typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router" },
};

const hcm = (stat: string, routeConfig: object, filters: object[], extra: object = {}) => ({
  name: "envoy.filters.network.http_connection_manager",
  typed_config: {
    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
    stat_prefix: stat,
    route_config: routeConfig,
    http_filters: [...filters, ROUTER],
    ...extra,
  },
});

const listener = (name: string, address: string, port: number, filterChain: object) => ({
  name,
  address: { socket_address: { address, port_value: port } },
  filter_chains: [filterChain],
});

function envoyConfig(s: Service) {
  const ingress = listener("ingress", "0.0.0.0", s.port, {
    transport_socket: {
      name: "envoy.transport_sockets.tls",
      typed_config: {
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
        // 顧客のアプリ（ブラウザ）は証明書を持たない。サービスからの受け口は、証明書を求める。
        require_client_certificate: s.ingress === "mtls",
        common_tls_context: {
          tls_certificate_sds_secret_configs: [sds("default")],
          ...(s.ingress === "mtls" ? { validation_context_sds_secret_config: sds("ROOTCA") } : {}),
        },
      },
    },
    filters: [
      hcm(
        "ingress",
        {
          name: "ingress",
          virtual_hosts: [{ name: "app", domains: ["*"], routes: [{ match: { prefix: "/" }, route: { cluster: "app" } }] }],
          // アプリは、トークンも証明書も受け取らない（2-2）
          request_headers_to_remove: ["authorization", "dpop", "x-forwarded-client-cert"],
        },
        [extAuthz("/ingress", ["authorization", "dpop", "x-forwarded-client-cert"], [{ prefix: "x-auth-" }])],
        { forward_client_cert_details: "SANITIZE_SET", set_current_client_cert_details: { uri: true } },
      ),
    ],
  });

  const toAuth = listener("egress-auth", "127.0.0.1", 15101, {
    filters: [
      hcm(
        "egress_auth",
        {
          name: "egress_auth",
          virtual_hosts: [
            {
              name: "auth",
              domains: ["*"],
              routes: [{ match: { prefix: "/" }, route: { cluster: "insurer_auth", host_rewrite_literal: `${host("insurer-auth")}:8443` } }],
            },
          ],
        },
        [],
      ),
    ],
  });

  const listeners: object[] = [ingress, toAuth];
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
    upstream("insurer_auth", "insurer-auth", 8443),
  ];

  if (s.next) {
    listeners.push(
      listener("egress-next", "127.0.0.1", 15102, {
        filters: [
          hcm(
            "egress_next",
            {
              name: "egress_next",
              virtual_hosts: [
                {
                  name: "next",
                  domains: ["*"],
                  routes: [{ match: { prefix: "/" }, route: { cluster: "next", host_rewrite_literal: `${host(s.next)}:9443` } }],
                },
              ],
              request_headers_to_remove: ["x-auth-ctx"],
            },
            // 出口では、受け口で確かめたトークンの控えを、次の段のトークンに替えてつける
            [extAuthz("/egress", ["x-auth-ctx"], [{ exact: "authorization" }])],
          ),
        ],
      }),
    );
    clusters.push(upstream("next", s.next, 9443));
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

const POD_SECURITY = { runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, runAsNonRoot: true };

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

const service = (name: string, port: number) => ({
  apiVersion: "v1",
  kind: "Service",
  metadata: meta(name),
  spec: { selector: { app: name }, ports: [{ name: "https", port, targetPort: port }] },
});

function serviceWorkload(s: Service) {
  const env = (vars: Record<string, string | undefined>) =>
    Object.entries(vars)
      .filter((e): e is [string, string] => e[1] !== undefined)
      .map(([name, value]) => ({ name, value }));
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta(`${s.name}-envoy`), data: { "envoy.json": JSON.stringify(envoyConfig(s)) } },
    service(s.name, s.port),
    deployment(s.name, s.name, { app: s.name }, {
      containers: [
        {
          name: "envoy",
          image: IMAGES.envoy,
          args: ["-c", "/etc/envoy/envoy.json", "--log-level", "warn"],
          ports: [{ containerPort: s.port }],
          volumeMounts: [SOCKET_MOUNT, { name: "envoy", mountPath: "/etc/envoy" }],
        },
        {
          name: "token-guard",
          image: IMAGES.node,
          command: ["node", "packages/token-guard/src/server.ts"],
          env: env({
            SERVICE: s.name,
            NAMESPACE: ns,
            ISSUER,
            INGRESS_PROOF: s.ingress,
            ALLOWED_CALLERS: s.callers.join(","),
            NEXT_SERVICE: s.next,
            DEFENSES_OFF: DEFENSES_OFF || undefined,
          }),
        },
        {
          name: "app",
          image: IMAGES.node,
          command: ["node", "packages/hop-app/src/server.ts"],
          env: env({ SERVICE: s.name, NEXT_URL: s.next ? "http://127.0.0.1:15102/hop" : undefined }),
        },
      ],
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
          env: [
            { name: "SPRING_PROFILES_ACTIVE", value: "k8s" },
            { name: "SVID_DIR", value: "/svid" },
            { name: "ISSUER", value: ISSUER },
            { name: "NAMESPACE", value: ns },
            { name: "TRUST_DOMAIN", value: TRUST_DOMAIN },
          ],
          ports: [{ containerPort: 8443 }],
          resources: { requests: { memory: "256Mi" }, limits: { memory: "512Mi" } },
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
        env: [
          { name: "NAMESPACE", value: ns },
          { name: "SERVICE_ACCOUNT", value: p.sa },
        ],
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
const allow = (app: string, port: number, callers: string[]) => [
  policy(`${app}-ingress`, {
    podSelector: { matchLabels: { app } },
    policyTypes: ["Ingress"],
    ingress: [{ from: from(...callers), ports: [{ port }] }],
  }),
  ...callers.map((caller) =>
    policy(`${caller}-to-${app}`, {
      podSelector: { matchLabels: { app: caller } },
      policyTypes: ["Egress"],
      egress: [{ to: from(app), ports: [{ port }] }],
    }),
  ),
];

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
  // 保険会社のシステムは、トークンを確かめる公開鍵を、認可サーバーから取る
  ...allow("insurer-auth", 8443, ["sales-agent", "insurer-mcp", "insurer-backend", "probe"]),
  ...allow("sales-agent", 8443, ["probe"]),
  ...allow("insurer-mcp", 9443, ["sales-agent", "probe"]),
  ...allow("insurer-backend", 9443, ["insurer-mcp", "probe"]),
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
