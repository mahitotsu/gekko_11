// 名前空間ごとのマニフェストを組み立て、JSON の List で標準出力に書く（kubectl apply -f - で使う）。
// 使い方: node deploy/render.ts <secure|vulnerable>
// secure は良い実装だけで動き、vulnerable は防御を 1 つずつ外せる（D-20）。構成は同じである。

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { ns, vulnerable } from "./render/common.ts";
import { PROBES, SERVICES, SERVICE_ACCOUNTS } from "./render/services.ts";
import { HELPER_CONFIG, HELPER_JWT_CONFIG, authWorkload, meta, probe, serviceWorkload } from "./render/kubernetes.ts";
import { entranceWorkload } from "./render/entrance.ts";
import { lokiWorkload } from "./render/logging.ts";
import { networkPolicies } from "./render/network.ts";

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

/** マニフェストに入らない値のハッシュ。Claude の認証情報（secure だけ）と、bundle の受け口の証明書（deploy/cluster.sh が渡す）。 */
const OUTSIDE: Record<string, string | undefined> = {
  "sales-agent": vulnerable ? undefined : process.env.CLAUDE_TOKEN_SHA,
  "insurer-login": process.env.BUNDLE_CA_SHA,
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- マニフェストは種類ごとに形が違う JSON で、Deployment の欄だけを読み書きする
function stamp(item: any) {
  if (item.kind !== "Deployment") return item;
  const spec = item.spec.template.spec;
  const images = [...(spec.initContainers ?? []), ...spec.containers].map((c: { image: string }) => imageId(c.image));
  const configs = (spec.volumes ?? [])
    .flatMap((v: { configMap?: { name: string } }) => (v.configMap ? [v.configMap.name] : []))
    .map((name: string) => (items as { kind: string; metadata: { name: string }; data?: unknown }[]).find((i) => i.kind === "ConfigMap" && i.metadata.name === name)?.data);
  const revision = createHash("sha256").update(JSON.stringify({ images, configs, outside: OUTSIDE[item.metadata.name] })).digest("hex").slice(0, 16);
  item.spec.template.metadata.annotations = { "gekko11/revision": revision };
  return item;
}

console.log(JSON.stringify({ apiVersion: "v1", kind: "List", items: items.map(stamp) }, null, 2));
