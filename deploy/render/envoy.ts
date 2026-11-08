import { host, spiffeId } from "./common.ts";
import { type Egress, type Service } from "./services.ts";

// ---- Envoy ----------------------------------------------------------------

export const sds = (name: string) => ({
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

export const local = (name: string, port: number) => ({
  name,
  type: "STATIC",
  load_assignment: {
    cluster_name: name,
    endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: "127.0.0.1", port_value: port } } } }] }],
  },
});

/** サービスどうしが mTLS で呼ぶポート。 */
export const portOf = (target: Egress["target"]) => (target === "insurer-auth" || target === "insurer-login" || target === "sales-agent" ? 8443 : 9443);

/**
 * 相手の SPIFFE ID を確かめて、SVID で mTLS をかける上流。
 * 接続は要求ごとにつなぎ直し、そのときの SVID で示す。使い回すと、SVID が入れ替わった後も前の証明書で示し続け、
 * 新しい証明書に結んだトークンと食い違う（F-G54）。
 */
export const upstream = (name: string, service: string, port: number, presentSvid = true) => ({
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

export const EXT_AUTHZ = "envoy.filters.http.ext_authz";

export const extAuthz = (pathPrefix: string, requestHeaders: string[], upstreamHeaders: object[]) => ({
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

export const NO_AUTHZ = {
  [EXT_AUTHZ]: { "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute", disabled: true },
};

export const ROUTER = {
  name: "envoy.filters.http.router",
  typed_config: { "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router" },
};

/** アクセスログ。パスにトークンが入っていないことを確かめるのに使う（G24）。 */
export const ACCESS_LOG = [
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

export const SPIRE_AGENT_CLUSTER = {
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

export const hcm = (stat: string, routeConfig: object, filters: object[], extra: object = {}) => ({
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

export const listener = (name: string, address: string, port: number, filterChain: object) => ({
  name,
  address: { socket_address: { address, port_value: port } },
  filter_chains: [filterChain],
});

export function envoyConfig(s: Service) {
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
  const ingress = inbound("ingress", s.port, s.ingress === "mtls" || Boolean(s.clientCert));
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
                  routes: [{ match: { prefix: "/" }, route: { cluster, host_rewrite_literal: e.host ?? `${host(e.target)}:${portOf(e.target)}`, timeout: "120s" } }],
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
