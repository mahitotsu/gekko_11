import { ADMIN, AGENT_INTERNAL, AUTH_JWKS_URL, IMAGES, ISSUER, LOGIN_EGRESS, LOGIN_ISSUER, LOGIN_JWKS_URL, TRUST_DOMAIN, host, ns, vulnerable } from "./common.ts";
import { PROBES, type Service } from "./services.ts";
import { SPIRE_AGENT_CLUSTER, envoyConfig, hcm, listener, upstream } from "./envoy.ts";

// ---- Kubernetes -----------------------------------------------------------

export const meta = (name: string, labels: Record<string, string> = {}) => ({ name, namespace: ns, labels });

export const SOCKET_VOLUME = { name: "spire-agent-socket", hostPath: { path: "/run/spire/sockets", type: "Directory" } };
export const SOCKET_MOUNT = { name: "spire-agent-socket", mountPath: "/run/spire/sockets", readOnly: true };
export const SVID_VOLUME = { name: "svid", emptyDir: {} };
export const SVID_MOUNT = { name: "svid", mountPath: "/svid" };

/** SVID をファイルに書き出し、入れ替える（native sidecar）。 */
export const HELPER_CONFIG = `agent_address = "/run/spire/sockets/agent.sock"
cert_dir = "/svid"
daemon_mode = true
svid_file_name = "svid.pem"
svid_key_file_name = "svid_key.pem"
svid_bundle_file_name = "svid_bundle.pem"
`;
export const helperSidecar = {
  name: "spiffe-helper",
  image: IMAGES.helper,
  restartPolicy: "Always",
  args: ["-config", "/config/helper.conf"],
  volumeMounts: [SOCKET_MOUNT, SVID_MOUNT, { name: "helper-config", mountPath: "/config" }],
};
/** 監査サービスの分。ログインサーバーの発行者を宛先にした JWT-SVID も、ファイルに書き出す（D-38）。 */
export const HELPER_JWT_CONFIG = `${HELPER_CONFIG}jwt_svids = [{jwt_audience="${LOGIN_ISSUER}", jwt_svid_file_name="jwt_svid.token"}]
`;
export const HELPER_CONFIG_VOLUME = { name: "helper-config", configMap: { name: "spiffe-helper" } };
export const waitForSvid = (cmd: string) => ["sh", "-c", `until [ -s /svid/svid_bundle.pem ]; do sleep 1; done; exec ${cmd}`];

/** ポートが開いたら準備ができたとみなす。kubelet からの通信は NetworkPolicy で拒むので、コンテナーの中で確かめる。 */
export const ready = (port: number) => ({
  readinessProbe: {
    exec: { command: ["bash", "-c", `exec 3<>/dev/tcp/127.0.0.1/${port}`] },
    periodSeconds: 3,
    failureThreshold: 60,
  },
});

export const POD_SECURITY = { runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, runAsNonRoot: true };

export const env = (vars: Record<string, string | undefined>) =>
  Object.entries(vars)
    .filter((e): e is [string, string] => e[1] !== undefined)
    .map(([name, value]) => ({ name, value }));

export function deployment(name: string, sa: string, labels: Record<string, string>, spec: object) {
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

export const service = (name: string, ...ports: number[]) => ({
  apiVersion: "v1",
  kind: "Service",
  metadata: meta(name),
  spec: {
    selector: { app: name },
    // 監査サービスには、防御を外す受け口がない
    ports: [...ports, ...(vulnerable && name !== "insurer-audit" ? [ADMIN.tokenGuard, ADMIN.app] : [])].map((port) => ({ name: `p${port}`, port, targetPort: port })),
  },
});

export function serviceWorkload(s: Service) {
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
        PUBLIC_ORIGIN: s.ingress === "dpop" ? AGENT_INTERNAL : undefined,
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
export function authEgressConfig() {
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

export function authWorkload() {
  return [
    { apiVersion: "v1", kind: "ConfigMap", metadata: meta("insurer-auth-envoy"), data: { "envoy.json": JSON.stringify(authEgressConfig()) } },
    service("insurer-auth", 8443),
    deployment("insurer-auth", "insurer-auth", { app: "insurer-auth" }, {
      // 利用者の passkey の公開鍵を、ログインサーバーの管理の API から読むため、JWT-SVID も書き出す（D-42）
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
            LOGIN_URL: `http://127.0.0.1:${LOGIN_EGRESS}`,
            JWT_SVID_FILE: "/svid/jwt_svid.token",
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
      volumes: [SOCKET_VOLUME, SVID_VOLUME, { name: "helper-config", configMap: { name: "spiffe-helper-jwt" } }, { name: "envoy", configMap: { name: "insurer-auth-envoy" } }],
    }),
  ];
}


export const probe = (p: (typeof PROBES)[number]) =>
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
    volumes: [SOCKET_VOLUME, SVID_VOLUME, "jwtSvid" in p ? { name: "helper-config", configMap: { name: "spiffe-helper-jwt" } } : HELPER_CONFIG_VOLUME],
  });
