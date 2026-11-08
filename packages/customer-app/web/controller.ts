// 申込みの進め方（D-29、D-34、P-18）。営業 AI エージェントと回を重ね、道具の呼び出しをカードにする。画面の部品から切り離す。
import { createLocalJWKSet, type JSONWebKeySet } from "jose";
import { reconcile, type Copy } from "../src/reconcile.ts";
import { createAgent, statusOf, type Agent } from "./agent.ts";
import { usedPasskey, type Config, type Device, type Session } from "./auth.ts";
import { verifyOffer, type Application, type Intent, type Offer } from "./checks.ts";
import { challengeOf } from "./codec.ts";
import type { Action, State } from "./conversation.ts";
import { signWithPasskey } from "./passkey.ts";

/**
 * passkey での署名ができなかったときの知らせ。取り消しと時間切れのほか、この端末に passkey がない場合も同じ誤りになる
 * （ブラウザは、利用者を守るため、区別を教えない。D-43）。
 */
export const PASSKEY_FAILED = "passkey で署名できませんでした。取り消したか時間切れなら、もう一度ボタンを押してください。この端末にパスキーがないときは、「パスキー」の欄の「この端末にパスキーを追加する」で作ってください。";

type Notice = { contract: { contractId?: string; nonce: string; plan: { name: string } } };
const LABEL = { match: "一致", mismatch: "食い違い", missing: "未着", unexpected: "覚えのない契約" };
const RECONCILE_TRIES = 5;
const RECONCILE_WAIT_MS = 2000;

const load = <T>(s: Storage, key: string): T | undefined => {
  const v = s.getItem(key);
  return v ? (JSON.parse(v) as T) : undefined;
};

/** 届いた全ての契約と全ての写しを照合し、画面の行にする。 */
export async function reconciled(session: Session, device: Device) {
  const notices = (await (await fetch(`/api/inbox/${device.inbox}`)).json()) as Notice[];
  const copies = load<(Copy & { plan: { name?: string } })[]>(localStorage, `copies:${session.sub}`) ?? [];
  // どの契約の行かを示す: 届いた契約の番号と案、届いていなければ写しの案
  const which = (nonce: string) => {
    const n = notices.find((x) => x.contract.nonce === nonce)?.contract;
    const c = copies.find((x) => x.nonce === nonce);
    return n ? `${n.contractId ?? ""} ${n.plan.name}` : `${c?.plan.name ?? ""}（契約の番号なし）`;
  };
  return reconcile(copies, notices as never).map((r) => ({
    nonce: r.nonce,
    status: r.status as string,
    text: `${which(r.nonce)} — ${r.status === "match" ? LABEL.match : `${LABEL[r.status]}: ${r.diffs.join("、")}`}`,
  }));
}

export function createController(deps: {
  cfg: Config;
  enabled: (id: string) => boolean;
  session: Session;
  device: Device;
  dispatch: (action: Action) => void;
  /** 今の状態を読む（非同期の処理の途中でも、最新を読む）。 */
  state: () => State;
}) {
  const { cfg, enabled, session, device, dispatch, state } = deps;
  // 営業 AI エージェントは、BFF が A と proof を付けて呼ぶ。画面は、BFF の受け口を、事前確認の要るヘッダーを付けて呼ぶ（D-41）
  const url = "/bff/agui";
  const headers = async () => ({ "x-bff": "1" });
  let agent: Agent = createAgent(url, headers);
  /** 始め直すと増える。古い回のイベントと照合を捨てる。 */
  let generation = 0;
  /** 回は 1 つずつ走らせる。走っている間に答えが決まっても、次の回に回す。 */
  let queue: Promise<void> = Promise.resolve();

  const fail = (e: unknown) => {
    const err = e as Error;
    dispatch({ type: "error", message: err?.name === "NotAllowedError" ? PASSKEY_FAILED : (err?.message ?? String(e)) });
  };

  /** ログインの有効期間が切れたカード（BFF が A を更新できない）。送れなかった申込書の写しは、端末から消す（受信箱に未着として残さない）。 */
  function expired() {
    const nonce = state().submitted;
    if (nonce) {
      const copies = load<Copy[]>(localStorage, `copies:${session.sub}`) ?? [];
      localStorage.setItem(`copies:${session.sub}`, JSON.stringify(copies.filter((c) => c.nonce !== nonce)));
      dispatch({ type: "clearSubmitted" });
    }
    dispatch({ type: "card", data: { kind: "expired" } });
    dispatch({ type: "busy", busy: false });
  }

  async function showTool(id: string, name: string, args: Record<string, any>) {
    if (name === "ask_customer") return dispatch({ type: "card", data: { kind: "ask", toolCallId: id, question: args.question, options: args.options } });
    if (name === "present_intent") return dispatch({ type: "card", data: { kind: "intent", toolCallId: id, doc: args.intent as Intent } });
    if (name === "present_application") return dispatch({ type: "card", data: { kind: "application", toolCallId: id, doc: args.application as Application } });
    if (name === "present_offers") {
      const carried = args.offer as Offer;
      let offer = carried;
      let tampered = false;
      if (enabled("G22")) {
        // 案は、保険会社の署名を確かめた中身から描く
        const keys = createLocalJWKSet((await (await fetch("/offers-jwks.json")).json()) as JSONWebKeySet);
        const v = await verifyOffer(carried, keys, session.sub).catch(async (e: Error) => {
          answerTool(id, { declined: true, reason: "提示の署名を確かめられない" });
          throw new Error(`提示の署名を確かめられない: ${e.message}`);
        });
        offer = v.offer;
        tampered = v.tampered;
      }
      return dispatch({ type: "card", data: { kind: "offers", toolCallId: id, message: args.message, reasons: args.reasons, offer, verified: enabled("G22"), tampered } });
    }
    answerTool(id, { error: `この画面にない道具: ${name}` });
  }

  /** 1 回分を走らせ、道具なしで番が終わったら、続きか完了のカードを出す。 */
  async function run() {
    const mine = generation;
    const current = () => mine === generation;
    dispatch({ type: "busy", busy: true });
    let called = false;
    let failed = false;
    const tools: Promise<void>[] = [];
    const once = () =>
      agent.run({
        onText: (content) => current() && dispatch({ type: "text", content }),
        onToolCall: (id, name, args) => {
          if (!current()) return;
          called = true;
          tools.push(showTool(id, name, args).catch(fail));
        },
        onRunError: (message) => {
          if (!current()) return;
          failed = true;
          fail(new Error(message));
        },
      });
    try {
      // A の更新と送り直しは、BFF が行う（P-18）。BFF が 401 を返すのは、ログインし直すしかないときである
      await once();
      await Promise.all(tools);
    } catch (e) {
      if (!current()) return; // 始め直した: 止めた回の失敗は見せない
      dispatch({ type: "submitting", submitting: false });
      if (statusOf(e) === 401) return expired();
      if (failed) return;
      throw e;
    }
    if (!current()) return;
    dispatch({ type: "submitting", submitting: false });
    if (!called && !failed) {
      if (state().submitted) finish();
      else dispatch({ type: "card", data: { kind: "continue" } });
    }
    dispatch({ type: "busy", busy: false });
  }

  const enqueue = () => {
    queue = queue.then(() => run()).catch(fail);
    return queue;
  };

  /** 顧客の答えを tool message にして、次の回を走らせる。 */
  function answerTool(id: string, content: unknown) {
    agent.answer(id, typeof content === "string" ? content : JSON.stringify(content));
    dispatch({ type: "error" });
    return enqueue();
  }

  async function checkSession(): Promise<string | undefined> {
    const rows = (await reconciled(session, device)).filter((r) => r.nonce === state().submitted);
    dispatch({ type: "reconcile", rows });
    return rows[0]?.status;
  }

  /**
   * 申込みの完了カード。押さなくても照合する。直送は少し遅れて届くので、未着なら待ち直す。
   * それでも未着なら、営業 AI エージェントが提出していないこともあるので、頼み直せるようにする。
   */
  function finish() {
    const mine = generation;
    dispatch({ type: "card", data: { kind: "finish" } });
    void (async () => {
      for (let i = 0; i < RECONCILE_TRIES; i++) {
        if (mine !== generation) return;
        if ((await checkSession()) !== "missing") return;
        await new Promise((r) => setTimeout(r, RECONCILE_WAIT_MS));
      }
      if (mine === generation) dispatch({ type: "reconcileGaveUp" });
    })().catch(fail);
  }

  return {
    fail,
    /** 始め直す。走っている回を止め、会話を新しくする。サーバーの古い会話は、使われなくなって捨てられる。 */
    startOver() {
      agent.abort();
      generation++;
      agent = createAgent(url, headers);
      queue = Promise.resolve();
      dispatch({ type: "reset" });
    },
    say(content: string) {
      agent.say(content);
      dispatch({ type: "error" });
      dispatch({ type: "started" });
      return enqueue();
    },
    answerTool,
    conclude: (id: number, result: string) => dispatch({ type: "conclude", id, result }),
    /**
     * 署名して答える。申込書は、顧客が承認した写しを端末に残す（事後の照合に使う）。
     * 端末の確認画面が出るまで数秒かかることがあるので、その間は二度押しを受け付けない（答えを 2 回送らない）。
     */
    async sign(id: string, step: "intent" | "application", doc: Intent | Application, onSigned: () => void) {
      if (state().signing) return;
      dispatch({ type: "error" });
      dispatch({ type: "signing", signing: true });
      let assertion: Awaited<ReturnType<typeof signWithPasskey>>;
      try {
        assertion = await signWithPasskey(await challengeOf(doc), cfg.rpId, session.passkeys?.passkeys ?? []);
      } finally {
        dispatch({ type: "signing", signing: false });
      }
      // どの passkey がこの端末で使えたかを覚え、「パスキー」の欄で印を付ける（D-43）
      usedPasskey.set(session.sub, assertion.id);
      onSigned();
      if (step === "application") {
        const copies = load<Copy[]>(localStorage, `copies:${session.sub}`) ?? [];
        localStorage.setItem(`copies:${session.sub}`, JSON.stringify([...copies, doc as unknown as Copy]));
        dispatch({ type: "submitted", nonce: doc.nonce });
      }
      return answerTool(id, { [step]: doc, assertion });
    },
    checkSession,
  };
}

export type Controller = ReturnType<typeof createController>;
