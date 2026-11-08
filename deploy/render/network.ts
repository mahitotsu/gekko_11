import { ADMIN, ENTRANCE, vulnerable } from "./common.ts";
import { SERVICES } from "./services.ts";
import { meta } from "./kubernetes.ts";

// ---- NetworkPolicy: 全て拒否から始め、2 章の経路だけを許す。名前空間をまたぐ通信は許さない ----

export const policy = (name: string, spec: object) => ({
  apiVersion: "networking.k8s.io/v1",
  kind: "NetworkPolicy",
  metadata: meta(name),
  spec,
});
export const from = (...apps: string[]) => apps.map((app) => ({ podSelector: { matchLabels: { app } } }));
export const allow = (app: string, ports: number[], callers: string[], suffix = "") => [
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

export const PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

export const networkPolicies = [
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
  ...allow("insurer-auth", [8443], ["sales-agent", "insurer-mcp", "insurer-backend", "customer-app", "probe"]),
  // ログインサーバーは、JWT-SVID を確かめる公開鍵を、SPIRE の bundle の受け口から取る（D-38）
  policy("insurer-login-to-spire", {
    podSelector: { matchLabels: { app: "insurer-login" } },
    policyTypes: ["Egress"],
    egress: [{ to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "spire" } }, podSelector: { matchLabels: { app: "spire-server" } } }], ports: [{ port: 8443 }] }],
  }),
  ...SERVICES.flatMap((s) => allow(s.name, [s.port, ...(s.mtlsPort ? [s.mtlsPort] : [])], [...s.callers, "probe"])),
  // クラスタの入口: 外から入口へ。入口からは、ブラウザが使う 4 つの受け口へだけ（営業 AI エージェントは、BFF からだけ受ける。D-41）
  policy("entrance-ingress", { podSelector: { matchLabels: { app: "entrance" } }, policyTypes: ["Ingress"], ingress: [{ ports: [{ port: ENTRANCE.listen }] }] }),
  ...["insurer-auth", "insurer-login", "customer-app", "insurer-audit"].flatMap((app) => allow(app, [8443], ["entrance"], "-entrance")),
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
