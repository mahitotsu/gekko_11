// 会話（AG-UI の thread）ごとの状態と、AG-UI のイベントの列（D-29）。Claude と台本の両方が、これを通して顧客とやりとりする。
// 画面側の道具（顧客への質問と書類の提示）を呼ぶと、イベントを出してその回を区切り、次の回の tool message を待つ。
// 書類の識別子と署名の値は、LLM ではなく、ここが直前の提示と画面の回答から入れる（D-27）。
import { createHash, randomUUID } from "node:crypto";
import canonicalize from "canonicalize";
import { EventType, type BaseEvent } from "@ag-ui/core";
import { applicationOf, intentOf, type Application, type Intent, type Offer } from "./draft.ts";
import type { Plan } from "./scripted.ts";

/** 画面側の道具。営業 AI エージェントが呼び、顧客のアプリが画面で答える。 */
export const FRONTEND_TOOLS = ["ask_customer", "present_offers", "present_intent", "present_application"] as const;
export type FrontendTool = (typeof FRONTEND_TOOLS)[number];

/** 会話の記録で伏せる欄。トークン、署名の値、提示の JWS は残さない（D-32）。 */
const SECRET_KEYS = new Set(["assertion", "intentAssertion", "intent_assertion", "signature", "intentSignature", "offerJws", "offer_jws", "token"]);

/** 値を複製し、伏せる欄を「（伏せた）」に置き換える。 */
export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEYS.has(k) ? "（伏せた）" : redact(v)]));
  }
  return value;
}

/** JCS（RFC 8785）で正規化した内容の SHA-256 の base64url。事務サービスのハッシュと同じ算出（監査の突き合わせ。D-32）。 */
export const digest = (value: unknown) => createHash("sha256").update(canonicalize(value) ?? "").digest("base64url");

/** 動いているモデル（Claude か台本）。 */
const model = () =>
  process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY ? (process.env.CLAUDE_MODEL ?? "claude-haiku-5-5") : "scripted";

/** 回の区切り。PAUSE は顧客の答えを待つ、END は営業 AI エージェントの番が終わった。 */
type Item = BaseEvent | { pause: true } | { end: true; error?: string };

export interface Signed {
  intent?: Intent;
  intentAssertion?: { response: { signature: string } } & Record<string, unknown>;
  application?: Application;
  assertion?: unknown;
}

export class Thread {
  readonly id: string;
  readonly sub: string;
  /** 最新の回で token-guard が渡した、トークンの控え。事務サービスを呼ぶときに使う。 */
  ctx = "";
  /** 最新の回の、確かめた主張（取決めを含む）。 */
  claims = "";
  /** 直前に事務サービスから受け取った提示。 */
  offer?: Offer;
  /** 顧客が署名した書類。画面が返した、顧客が実際に署名した内容をそのまま持ち、提出する。 */
  signed: Signed = {};
  /** 顧客が画面で選んだ案（画面が返した案の中身）。 */
  chosen?: Plan;
  lastUsed = Date.now();

  private inbox: string[] = [];
  private inboxWake?: () => void;
  private items: Item[] = [];
  private wake?: () => void;
  private pending?: { id: string; resolve: (content: string) => void };

  constructor(id: string, sub: string) {
    this.id = id;
    this.sub = sub;
  }

  /**
   * 会話の記録（監査の形。D-32）を、1 行の JSON で書く。Alloy が集め、名前空間の Loki に入れる。
   * 本文を残すが、トークン、署名の値、提示の JWS は伏せる。営業 AI エージェントは書き換えうる者なので、監査では証拠の 1 つとして扱う。
   */
  record(event: string, detail: Record<string, unknown> = {}) {
    const entry = { kind: "conversation", at: Math.floor(Date.now() / 1000), service: "sales-agent", thread: this.id, sub: this.sub, model: model(), event, ...detail };
    console.log(JSON.stringify({ audit: redact(entry) }));
  }

  /** 顧客の文（user message）を、営業 AI エージェントに渡す。 */
  tell(text: string) {
    this.record("customer_text", { text });
    this.inbox.push(text);
    this.inboxWake?.();
  }

  /** 顧客の文を、届いた順に返す（営業 AI エージェントの番の始まり）。 */
  async *messages(): AsyncGenerator<string> {
    for (;;) {
      while (this.inbox.length) yield this.inbox.shift()!;
      await new Promise<void>((r) => (this.inboxWake = r));
      this.inboxWake = undefined;
    }
  }

  /** 事務サービスから受け取った提示を覚え、会話の記録に、nonce と識別子を残す。 */
  setOffer(offer: Offer) {
    this.offer = offer;
    this.record("agent_tool", { name: "get_offers", nonce: offer.nonce, offerSetId: offer.offerSetId });
  }

  get waitingFor(): string | undefined {
    return this.pending?.id;
  }

  private push(item: Item) {
    this.items.push(item);
    this.wake?.();
  }

  /** 次の区切り（PAUSE か END）までのイベントを、届いた順に返す。 */
  async *drain(): AsyncGenerator<Item> {
    for (;;) {
      while (this.items.length) {
        const item = this.items.shift()!;
        yield item;
        if ("pause" in item || "end" in item) return;
      }
      await new Promise<void>((r) => (this.wake = r));
      this.wake = undefined;
    }
  }

  /** 営業 AI エージェントの文を、顧客に送る。 */
  say(text: string) {
    if (!text.trim()) return;
    this.record("agent_text", { text });
    const messageId = randomUUID();
    this.push({ type: EventType.TEXT_MESSAGE_START, messageId, role: "assistant" } as BaseEvent);
    this.push({ type: EventType.TEXT_MESSAGE_CONTENT, messageId, delta: text } as BaseEvent);
    this.push({ type: EventType.TEXT_MESSAGE_END, messageId } as BaseEvent);
  }

  /** 営業 AI エージェントの番が終わった。 */
  end(error?: string) {
    this.push({ end: true, error });
  }

  /**
   * 画面側の道具を呼び、顧客の答えを待つ。LLM が決めた値（llmArgs）に、決まった処理が識別子と署名の値を足して、画面へ送る。
   * 返すのは、LLM に渡す答えの文。
   */
  async frontend(name: FrontendTool, llmArgs: Record<string, unknown>): Promise<string> {
    const args = this.argsFor(name, llmArgs);
    const toolCallId = randomUUID();
    // 示した書類のハッシュを、決まった処理が残す。LLM の会話の履歴には入らない。監査サービスが、事務サービスのハッシュと比べる
    const document = name === "present_intent" ? args.intent : name === "present_application" ? args.application : undefined;
    this.record("frontend_tool", {
      name,
      args: name === "present_offers" ? offerSummary(args) : args,
      ...(document ? { document_hash: digest(document) } : {}),
    });
    this.push({ type: EventType.TOOL_CALL_START, toolCallId, toolCallName: name } as BaseEvent);
    this.push({ type: EventType.TOOL_CALL_ARGS, toolCallId, delta: JSON.stringify(args) } as BaseEvent);
    this.push({ type: EventType.TOOL_CALL_END, toolCallId } as BaseEvent);
    const answer = new Promise<string>((resolve) => (this.pending = { id: toolCallId, resolve }));
    this.push({ pause: true });
    return this.accept(name, args, await answer);
  }

  /** 次の回の tool message で、待っている道具に答える。 */
  answer(toolCallId: string, content: string): boolean {
    if (this.pending?.id !== toolCallId) return false;
    const { resolve } = this.pending;
    this.pending = undefined;
    let answer: unknown = content;
    try {
      answer = JSON.parse(content);
    } catch {
      // 文の答えは、そのまま残す
    }
    this.record("customer_answer", { answer });
    resolve(content);
    return true;
  }

  private argsFor(name: FrontendTool, llm: Record<string, unknown>): Record<string, unknown> {
    switch (name) {
      case "ask_customer":
        return { question: String(llm.question ?? ""), options: (llm.options as string[]) ?? [] };
      case "present_offers":
        if (!this.offer) throw new Error("示す提示がない（先に get_offers を使う）");
        return { message: String(llm.message ?? ""), offer: this.offer };
      case "present_intent":
        if (!this.offer) throw new Error("示す提示がない（先に get_offers を使う）");
        return { intent: intentOf(this.sub, this.offer, String(llm.planId), String(llm.wish ?? ""), this.chosen) };
      case "present_application":
        if (!this.offer || !this.signed.intentAssertion) throw new Error("意向確認書面の署名がない（先に present_intent を使う）");
        return {
          application: applicationOf(this.sub, this.offer, String(llm.planId), this.signed.intentAssertion.response.signature, this.chosen),
        };
    }
  }

  /** 顧客の答えを受け取り、署名なら、顧客が署名した内容と署名を覚え、LLM に渡す文にする。 */
  private accept(name: FrontendTool, args: Record<string, unknown>, content: string): string {
    let answer: Record<string, unknown>;
    try {
      answer = JSON.parse(content) as Record<string, unknown>;
    } catch {
      return content;
    }
    if (answer.declined) return "顧客は、この書類への署名を断りました。";
    if (name === "present_intent" && answer.assertion) {
      this.signed = { intent: (answer.intent ?? args.intent) as Intent, intentAssertion: answer.assertion as Signed["intentAssertion"] };
      return "顧客は、意向確認書面に署名しました。";
    }
    if (name === "present_application" && answer.assertion) {
      this.signed = { ...this.signed, application: (answer.application ?? args.application) as Application, assertion: answer.assertion };
      return "顧客は、申込書に署名しました。submit_application で提出できます。";
    }
    if (name === "present_offers" && answer.planId) {
      this.chosen = answer.plan as Plan | undefined;
      return `顧客が選んだ案: ${String(answer.planId)}`;
    }
    return String(answer.answer ?? content);
  }
}

/** 提示は、nonce と識別子と案の一覧だけを残す（署名の JWS は残さない）。 */
function offerSummary(args: Record<string, unknown>) {
  const offer = args.offer as Offer;
  return { message: args.message, offer: { nonce: offer.nonce, offerSetId: offer.offerSetId, plans: offer.offerSet.plans } };
}

/** threadId ごとの会話。1 つの複製で動き、15 分使われなければ捨てる。 */
const threads = new Map<string, Thread>();
const IDLE_MS = 15 * 60_000;

export function threadFor(id: string, sub: string, start: (t: Thread) => void): Thread {
  const now = Date.now();
  for (const [k, t] of threads) if (now - t.lastUsed > IDLE_MS) threads.delete(k);
  let t = threads.get(id);
  if (t && t.sub !== sub) throw new Error("この会話は、ほかの顧客のものである");
  if (!t) {
    t = new Thread(id, sub);
    threads.set(id, t);
    start(t);
  }
  t.lastUsed = now;
  return t;
}
