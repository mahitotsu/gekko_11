import { IMAGES } from "./common.ts";
import { deployment, meta } from "./kubernetes.ts";

// ---- 記録の集約（D-30） -------------------------------------------------------
// 名前空間ごとに Loki を 1 つ置く。記録を届けるのは logging の名前空間の Alloy だけで、読むのは監査サービスだけである。

/** 単一のプロセスで、ファイルに保存する。保存期間は 7 日（compactor の retention）。 */
export const LOKI_CONFIG = `auth_enabled: false
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

export function lokiWorkload() {
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
