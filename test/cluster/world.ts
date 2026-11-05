// クラスタのシナリオのテストの基盤。手元から kubectl exec で probe を動かし、署名は手元で作る。
// secure は全ての防御が有効で、切り替えの受け口がない。vulnerable は、防御を 1 つずつ外せる（D-20）。
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import { parseSse } from "../../packages/customer-app/web/agui.ts";
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

/** ブラウザが入口を通って呼ぶ公開名（D-25）。 */
export const publicOrigin = (ns: Ns, name: "app" | "login" | "auth" | "agent" | "audit") => `http://${name}.${ns}.localhost:${ns === "vulnerable" ? 8082 : 8081}`;

export const TERMS = [{ type: "insurance_application", kinds: ["fixed", "lifetime"], maxBenefit: 1_200_000 }];

/** 顧客。ログイン、passkey の登録、A の受け取りは probe が行い、署名は手元で行う。 */
export class Customer {
  token = "";
  idToken = "";
  dpopKey: Json = {};
  authenticator!: AuthenticatorState;
  /** passkey と一緒に登録した受信箱の番号（直送の宛先）。 */
  inbox = "";

  readonly ns: Ns;
  readonly user: string;

  constructor(ns: Ns, user: string) {
    this.ns = ns;
    this.user = user;
  }

  get origin() {
    return publicOrigin(this.ns, "app");
  }

  async setup(terms: unknown = TERMS): Promise<this> {
    const r = await probe(this.ns, "probe-sales-agent", "customer-setup", { user: this.user, terms });
    if (r.status !== 200) throw new Error(`顧客の準備に失敗: ${JSON.stringify(r)}`);
    Object.assign(this, { token: r.token, idToken: r.idToken, dpopKey: r.dpopKey, authenticator: r.authenticator, inbox: r.inbox });
    return this;
  }

  /** 営業 AI エージェントの AG-UI の受け口に、1 回分（RunAgentInput）を、A と DPoP の proof で出す。返すのは、SSE のイベントの列。 */
  async agui(input: Json, proof: "good" | "none" | "other-key" = "good"): Promise<{ status: number; events: Json[]; body: unknown }> {
    const r = await probe(this.ns, "probe-sales-agent", "call-sales-agent", { path: "/agui", body: input, token: this.token, dpopKey: this.dpopKey, proof });
    return { status: r.status, events: typeof r.body === "string" ? parseSse(r.body) : [], body: r.body };
  }

  /**
   * 顧客のアプリの役で、営業 AI エージェントと会話を進める（D-29）。質問には最初の選択肢で答え、案は planId を選び、
   * 2 つの書類には、示された内容そのものに署名する。返すのは、提示の nonce と、全てのイベント。
   */
  async converse(planId: string, message = "案を見たい"): Promise<{ nonce: string; events: Json[] }> {
    const threadId = randomUUID();
    const messages: Json[] = [{ id: randomUUID(), role: "user", content: message }];
    const all: Json[] = [];
    let nonce = "";
    for (let i = 0; i < 8; i++) {
      const r = await this.agui({ threadId, runId: randomUUID(), messages, tools: [], state: {}, context: [], forwardedProps: {} });
      if (r.status !== 200) throw new Error(`営業 AI エージェントが断った: ${JSON.stringify(r.body)}`);
      all.push(...r.events);
      const error = r.events.find((e) => e.type === "RUN_ERROR");
      if (error) throw new Error(`営業 AI エージェントが止まった: ${error.message}`);
      const start = r.events.find((e) => e.type === "TOOL_CALL_START");
      if (!start) return { nonce, events: all };
      const args = JSON.parse(r.events.filter((e) => e.type === "TOOL_CALL_ARGS" && e.toolCallId === start.toolCallId).map((e) => e.delta).join(""));
      messages.push({ id: randomUUID(), role: "assistant", toolCalls: [{ id: start.toolCallId, type: "function", function: { name: start.toolCallName, arguments: JSON.stringify(args) } }] });
      let content: unknown;
      if (start.toolCallName === "ask_customer") content = args.options[0];
      if (start.toolCallName === "present_offers") {
        nonce = args.offer.nonce;
        content = { planId, plan: args.offer.offerSet.plans.find((p: Plan) => p.id === planId) };
      }
      if (start.toolCallName === "present_intent") content = { intent: args.intent, assertion: this.sign(args.intent) };
      if (start.toolCallName === "present_application") content = { application: args.application, assertion: this.sign(args.application) };
      messages.push({ id: randomUUID(), role: "tool", toolCallId: start.toolCallId, content: JSON.stringify(content) });
    }
    throw new Error("会話が終わらない");
  }

  /** 内容に署名する（顧客のアプリの画面で passkey を使う操作に当たる）。 */
  sign(content: unknown) {
    return sign(this.authenticator, `app.${this.ns}.localhost`, challengeOf(content), this.origin);
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
    return (await probe(this.ns, "probe-sales-agent", "notices", { inbox: this.inbox })).body as Json[];
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

/** 監査の担当（kansa）としてログインし、監査サービスの受け口を読む（D-31）。user を変えると、ほかの者のログインを試せる。 */
export const auditorGet = (ns: Ns, path: string, user = "kansa") => probe(ns, "probe-auditor", "auditor", { user, path });

/** 監査サービスが示す、契約ごとの突き合わせの結果の、点ごとの一致。 */
export const checksOf = (report: Json): Record<string, boolean> =>
  Object.fromEntries((report.checks as Json[]).map((c) => [String(c.name).replace(/（.*/, ""), c.ok as boolean]));

/**
 * 監査サービスの、契約ごとの突き合わせ（D25）。Loki に記録が届くまで数秒かかるので、until を満たすまで問い合わせ直す。
 * 満たさないまま時間が過ぎたら、最後の結果を返す（テストの期待で、何が足りないかを示す）。
 */
export async function auditOf(ns: Ns, nonce: string, until: (report: Json) => boolean): Promise<Json> {
  let last: Json = {};
  for (let i = 0; i < 15; i++) {
    const r = await auditorGet(ns, `/api/contracts/${nonce}`);
    last = r.status === 200 ? (r.body as Json) : { status: r.status, body: r.body };
    if (r.status === 200 && until(last)) return last;
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  return last;
}

// ---- vulnerable の防御の切り替え（メモリ上だけ。切り替えた後と戻した後に読み返す） ----

/** 防御の ID と、それを持つ部品（サービスと管理のポート）。 */
const OWNER: Record<string, { service: string; port: number; path: string }> = {};
const own = (ids: string[], service: string, port: number, path = "/defenses") => ids.forEach((id) => (OWNER[`${service}:${id}`] = { service, port, path }));
own(["D3a", "D3b", "D3c"], "insurer-login", 9091);
own(["D3a", "D3b", "D3d", "D3e", "D3f", "D28"], "insurer-auth", 9091);
own(["D9", "D11", "D12", "D13", "D14", "D15", "D16", "D17", "D18"], "insurer-backend", 9091);
own(["D5", "D6", "D7", "D8", "D10", "D26", "D27", "D29"], "insurer-backend", 9090);
own(["D1", "D2", "D26", "D27", "D29"], "insurer-mcp", 9090);
own(["D20", "D26"], "sales-agent", 9090);
own(["D21", "D22", "D23"], "customer-app", 9091);

/** 外す防御。値は外し方（多くは "off"）。D26 と D27 は、サービスを付けて "D26@insurer-backend" のようにも書ける。 */
export type Gaps = Record<string, string>;

const PARTS = [
  { service: "insurer-login", port: 9091 },
  { service: "insurer-auth", port: 9091 },
  { service: "insurer-backend", port: 9091 },
  { service: "insurer-backend", port: 9090 },
  { service: "insurer-mcp", port: 9090 },
  { service: "sales-agent", port: 9090 },
  { service: "customer-app", port: 9091 },
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

// ---- 乗っ取られた窓口と、攻撃者の役 ----

/** 窓口の役が、自分の SVID で、トークンを替える（actor_token は自分のトークン）。 */
export async function exchangeAs(ns: Ns, who: Role, subject: string, audience: string, terms?: unknown): Promise<Json> {
  const once = async () => {
    const actor = (await probe(ns, who, "client-credentials")).body?.access_token;
    return probe(ns, who, "exchange", { subject, actor, audience, terms });
  };
  const r = await once();
  // actor_token を受け取ってから替えるまでの間に SVID が入れ替わると、前の証明書に結んだ actor_token は拒まれる（F-G54）。
  // token-guard と同じく、actor_token を取り直して 1 度だけやり直す
  return String(r.body?.error_description ?? "").includes("not bound to the requester certificate") ? once() : r;
}

/** 乗っ取られた営業 AI エージェント: 顧客の A を、事務サービス宛ての B に替える。 */
export async function atMcp(customer: Customer, terms?: unknown): Promise<string> {
  const r = await exchangeAs(customer.ns, "probe-sales-agent", customer.token, "insurer-mcp", terms);
  if (r.status !== 200) throw new Error(`B を受け取れない: ${JSON.stringify(r)}`);
  return r.body.access_token;
}

/** 事務サービスの MCP の道具を、トークンを付けて呼ぶ。 */
export const mcpCall = (ns: Ns, token: string, tool: string, args: Json = {}, who: Role = "probe-sales-agent") =>
  probe(ns, who, "mcp", { token, tool, args });

/** 申込みを、事務サービスの道具の引数の形にする。extras は、窓口が足せる欄。 */
export const applyArgs = (s: Submission, extras?: Json) => ({
  intent: s.intent,
  intent_assertion: s.intentAssertion,
  application: s.application,
  assertion: s.assertion,
  offer_jws: s.offerJws,
  ...(extras ? { extras } : {}),
});

/** 攻撃の材料として、正規の経路で、顧客宛ての提示を受け取る（防御の設定に左右されない）。 */
export async function offerFor(customer: Customer): Promise<Offer> {
  let r = await mcpCall(customer.ns, await atMcp(customer), "get_offers");
  // B を受け取ってから呼ぶまでの間に SVID が入れ替わると、前の証明書に結んだ B は拒まれる（F-G54）。B から取り直して 1 度だけやり直す
  if (String(r.body?.error ?? "").includes("相手の証明書に結ばれていない")) r = await mcpCall(customer.ns, await atMcp(customer), "get_offers");
  if (!r.body?.offerJws) throw new Error(`提示を受け取れない: ${JSON.stringify(r)}`);
  return r.body as Offer;
}

/** 保険会社のシステムへ、事務サービスを通らずに直接申し込む。 */
export const backendPost = (ns: Ns, token: string, body: unknown, who: Role = "probe-mcp-1") =>
  probe(ns, who, "call-service", { service: "insurer-backend", path: "/applications", token, body });

/** 監査の記録に、その nonce の契約があるか。 */
export async function contractsOf(ns: Ns, nonce: string): Promise<Json[]> {
  return (await records(ns)).contracts.filter((c) => c.contract.nonce === nonce);
}

export const ISSUER = (ns: Ns) => publicOrigin(ns, "auth");
export const LOGIN_ISSUER = (ns: Ns) => `${publicOrigin(ns, "login")}/realms/insurer`;
