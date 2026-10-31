// クラスタのシナリオのテストの基盤。手元から kubectl exec で probe を動かし、署名は手元で作る。
// secure は全ての防御が有効で、切り替えの受け口がない。vulnerable は、防御を 1 つずつ外せる（D-20）。
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { challengeOf, sign, type AuthenticatorState } from "./probe/webauthn.ts";

const run = promisify(execFile);

export type Ns = "secure" | "vulnerable";
export type Json = Record<string, any>;

/** probe の役。ServiceAccount が身元（SPIFFE ID）を決める。 */
export type Role = "probe-sales-agent" | "probe-mcp-1" | "probe-mcp-2" | "probe-intruder" | "probe-operator" | "probe-auditor";

export async function probe(ns: Ns, who: Role, command: string, args: object = {}): Promise<Json> {
  try {
    const { stdout } = await run(
      "kubectl",
      ["-n", ns, "exec", `deploy/${who}`, "-c", "probe", "--", "node", "test/cluster/probe/probe.ts", command, JSON.stringify(args)],
      { maxBuffer: 16 * 1024 * 1024 },
    );
    return JSON.parse(stdout.trim().split("\n").at(-1)!);
  } catch (e) {
    const out = (e as { stdout?: string }).stdout?.trim().split("\n").at(-1);
    if (out) return JSON.parse(out);
    throw e;
  }
}

export const TERMS = [{ type: "insurance_application", kinds: ["fixed", "lifetime"], maxBenefit: 1_200_000 }];

/** 顧客。ログイン、passkey の登録、A の受け取りは probe が行い、署名は手元で行う。 */
export class Customer {
  token = "";
  idToken = "";
  dpopKey: Json = {};
  authenticator!: AuthenticatorState;

  constructor(
    readonly ns: Ns,
    readonly user: string,
  ) {}

  get origin() {
    return `https://customer-app.${this.ns}.svc:8443`;
  }

  async setup(terms: unknown = TERMS): Promise<this> {
    const r = await probe(this.ns, "probe-sales-agent", "customer-setup", { user: this.user, terms });
    if (r.status !== 200) throw new Error(`顧客の準備に失敗: ${JSON.stringify(r)}`);
    Object.assign(this, { token: r.token, idToken: r.idToken, dpopKey: r.dpopKey, authenticator: r.authenticator });
    return this;
  }

  /** 営業 AI エージェントを、A と DPoP の proof で呼ぶ。 */
  salesAgent(path: string, body: unknown, proof: "good" | "none" | "other-key" = "good") {
    return probe(this.ns, "probe-sales-agent", "call-sales-agent", { path, body, token: this.token, dpopKey: this.dpopKey, proof });
  }

  /** 内容に署名する（顧客のアプリの画面で passkey を使う操作に当たる）。 */
  sign(content: unknown) {
    return sign(this.authenticator, `customer-app.${this.ns}.svc`, challengeOf(content), this.origin);
  }

  /** 案を選んで、意向確認と申込みに署名する（3 章の 3 段）。 */
  prepare(offer: Offer, planId: string, plan = offer.offerSet.plans.find((p) => p.id === planId)!): Submission {
    const intent = { customer: this.user, offerSetId: offer.offerSetId, planId, wish: "老後の生活費に備えたい", nonce: offer.nonce, expiresAt: offer.expiresAt };
    const intentAssertion = this.sign(intent);
    const application = {
      customer: this.user,
      plan,
      offerSetId: offer.offerSetId,
      intentSignature: intentAssertion.response.signature,
      nonce: offer.nonce,
      expiresAt: offer.expiresAt,
    };
    return { offerJws: offer.offerJws, intent, intentAssertion, application, assertion: this.sign(application) };
  }

  async notices(): Promise<Json[]> {
    return (await probe(this.ns, "probe-sales-agent", "notices", { customer: this.user })).body as Json[];
  }
}

export interface Plan {
  id: string;
  name: string;
  kind: string;
  benefit: number;
  monthly: number;
}

export interface Offer {
  offerJws: string;
  offerSet: { customer: string; plans: Plan[] };
  offerSetId: string;
  nonce: string;
  expiresAt: number;
}

export interface Submission {
  offerJws?: string;
  intent: Json;
  intentAssertion: Json | null;
  application: Json;
  assertion: unknown;
}

/** 監査の役が読む、契約の記録と直送の記録。 */
export async function records(ns: Ns): Promise<{ contracts: Json[]; outbox: Json[] }> {
  const r = await probe(ns, "probe-auditor", "audit");
  if (r.status !== 200) throw new Error(`監査の記録を読めない: ${JSON.stringify(r)}`);
  return r.body as { contracts: Json[]; outbox: Json[] };
}

// ---- vulnerable の防御の切り替え（メモリ上だけ。切り替えた後と戻した後に読み返す） ----

/** 防御の ID と、それを持つ部品（サービスと管理のポート）。 */
const OWNER: Record<string, { service: string; port: number; path: string }> = {};
const own = (ids: string[], service: string, port: number, path = "/defenses") => ids.forEach((id) => (OWNER[`${service}:${id}`] = { service, port, path }));
own(["D3a", "D3b", "D3c", "D3d", "D3e", "D3f"], "insurer-auth", 9091);
own(["D9", "D11", "D12", "D13", "D14", "D15", "D16", "D17", "D18"], "insurer-backend", 9091);
own(["D5", "D6", "D7", "D8", "D10", "D26", "D27"], "insurer-backend", 9090);
own(["D1", "D2", "D26", "D27"], "insurer-mcp", 9090);
own(["D20", "D26"], "sales-agent", 9090);

/** 外す防御。値は外し方（多くは "off"）。D26 と D27 は、サービスを付けて "D26@insurer-backend" のようにも書ける。 */
export type Gaps = Record<string, string>;

const PARTS = [
  { service: "insurer-auth", port: 9091 },
  { service: "insurer-backend", port: 9091 },
  { service: "insurer-backend", port: 9090 },
  { service: "insurer-mcp", port: 9090 },
  { service: "sales-agent", port: 9090 },
];

export async function setDefenses(gaps: Gaps): Promise<void> {
  const plan = new Map<string, Record<string, string>>(PARTS.map((p) => [`${p.service}:${p.port}`, {}]));
  for (const [key, how] of Object.entries(gaps)) {
    const [id, only] = key.split("@");
    const owners = Object.entries(OWNER).filter(([k]) => k.endsWith(`:${id}`) && (!only || k.startsWith(`${only}:`)));
    if (owners.length === 0) throw new Error(`外せない防御: ${key}`);
    for (const [, o] of owners) plan.get(`${o.service}:${o.port}`)![id!] = how;
  }
  await Promise.all(
    [...plan].map(async ([part, off]) => {
      const [service, port] = part.split(":");
      await probe("vulnerable", "probe-intruder", "admin", { service, port: Number(port), path: "/defenses", method: "PUT", body: { off } });
      const now = await probe("vulnerable", "probe-intruder", "admin", { service, port: Number(port), path: "/defenses" });
      if (!same(now.body?.off ?? {}, off)) {
        throw new Error(`防御の設定が効いていない: ${part} 期待 ${JSON.stringify(off)} 実際 ${JSON.stringify(now.body)}`);
      }
    }),
  );
}

const sorted = (o: Record<string, string>) => Object.fromEntries(Object.entries(o).sort());
const same = (a: Record<string, string>, b: Record<string, string>) => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));

/** 乗っ取られた営業 AI エージェント（手口 A8）の切り替え。vulnerable だけ。 */
export async function setTamper(on: boolean): Promise<void> {
  await probe("vulnerable", "probe-intruder", "admin", { service: "sales-agent", port: 9091, path: "/tamper", method: "PUT", body: { on } });
  const now = await probe("vulnerable", "probe-intruder", "admin", { service: "sales-agent", port: 9091, path: "/tamper" });
  if (now.body?.on !== on) throw new Error(`書き換えの設定が効いていない: ${JSON.stringify(now.body)}`);
}
