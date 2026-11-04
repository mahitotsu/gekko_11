// 顧客のアプリの画面（D-18）。ブラウザで動く公開クライアントで、トークンと鍵は端末の中に置く。
// ログインと passkey と受信箱の登録の後は、営業 AI エージェントと AG-UI でやりとりし、カードを積んで進む（D-29、D-34）。営業 AI エージェントが、
// 質問、案の提示、意向確認書面、申込書を、画面側の道具として呼び、この画面が顧客の答え（選択と署名）を返す。
// 契約内容は、営業 AI エージェントを通らずに受信箱へ届き、端末に残した写しと照合する（architecture の 3 章）。
import { createLocalJWKSet, createRemoteJWKSet, type JSONWebKeySet } from "jose";
import type { Message } from "@ag-ui/core";
import { reconcile, type Copy } from "../src/reconcile.ts";
import { AgentRefused, FRONTEND_TOOLS, runOnce, type AgentEvent } from "./agui.ts";
import {
  applicationRowsOf, intentRowsOf, termsRowsOf, verifyIdToken, verifyOffer, type Application, type Intent, type Offer, type Row,
} from "./checks.ts";
import { b64u, challengeOf, randomB64u, sha256 } from "./codec.ts";
import { loadDefenses } from "./defenses.ts";
import { createPasskey, dpopProof, signWithPasskey } from "./keys.ts";
import { markdownToHtml } from "./markdown.ts";

interface Config {
  issuer: string;
  agentOrigin: string;
  appOrigin: string;
  rpId: string;
  clientId: string;
  terms: unknown;
}

interface Session {
  token: string;
  sub: string;
  /** サインアウトのときに、認可サーバーへ示す（D-33）。 */
  idToken: string;
}

interface Device {
  credentialId: string;
  inbox: string;
}

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const show = (id: string, on = true) => $(id).toggleAttribute("hidden", !on);
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, testid?: string) => {
  const e: HTMLElementTagNameMap[K] = Object.assign(document.createElement(tag), props);
  if (testid) e.setAttribute("data-testid", testid);
  return e;
};
const store = {
  get: <T>(s: Storage, key: string): T | undefined => {
    const v = s.getItem(key);
    return v ? (JSON.parse(v) as T) : undefined;
  },
  set: (s: Storage, key: string, value: unknown) => s.setItem(key, JSON.stringify(value)),
};

/** エラーは、画面の上に固定した帯に出す（どこを見ていても見える）。passkey の取り消しは、日本語で案内する。 */
function fail(e: unknown) {
  const err = e as Error;
  $("error").textContent =
    err?.name === "NotAllowedError"
      ? "passkey の操作が取り消されたか、時間切れになりました。もう一度ボタンを押してください。"
      : (err?.message ?? String(e));
  show("error");
  setBusy(false);
}

const clearError = () => show("error", false);

/** 営業 AI エージェントが考えている間は、状態を示す。 */
function setBusy(busy: boolean) {
  $("agent-status").textContent = busy ? "営業 AI エージェントが考えています…" : "";
  $("agent-status").dataset.state = busy ? "busy" : "idle";
}

function table(rows: Row[], prefix: string): HTMLTableElement {
  const t = el("table");
  for (const row of rows) {
    const tr = t.insertRow();
    tr.insertCell().textContent = row.label;
    const td = tr.insertCell();
    td.textContent = row.value;
    td.dataset.testid = `${prefix}-${row.key}`;
  }
  return t;
}

const cfg = (await (await fetch("/config.json")).json()) as Config;
const enabled = await loadDefenses();
const redirectUri = `${cfg.appOrigin}/callback`;

// ---- 1. ログイン（認可コードと PKCE（S256）。D-12） ----

async function startLogin() {
  const login = { verifier: randomB64u(), state: randomB64u(16), nonce: randomB64u(16) };
  store.set(sessionStorage, "login", login);
  const q = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    scope: "openid apply",
    redirect_uri: redirectUri,
    state: login.state,
    nonce: login.nonce,
    code_challenge: b64u(await sha256(login.verifier)),
    code_challenge_method: "S256",
    authorization_details: JSON.stringify(cfg.terms),
  });
  location.assign(`${cfg.issuer}/oauth2/authorize?${q}`);
}

// ---- 2. 戻り先: DPoP に結んだトークン A を受け取り、ID トークンを確かめる（D21） ----

async function finishLogin(params: URLSearchParams) {
  const login = store.get<{ verifier: string; state: string; nonce: string }>(sessionStorage, "login");
  history.replaceState(null, "", "/");
  if (!login || params.get("state") !== login.state) throw new Error("ログインの state が違う");
  const tokenUrl = `${cfg.issuer}/oauth2/token`;
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof("POST", tokenUrl) },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: cfg.clientId,
      code: params.get("code") ?? "",
      redirect_uri: redirectUri,
      code_verifier: login.verifier,
    }),
  });
  const body = (await res.json()) as { access_token?: string; id_token?: string; error?: string };
  if (!res.ok || !body.access_token || !body.id_token) throw new Error(`トークンを受け取れない: ${body.error ?? res.status}`);
  let sub: string;
  if (enabled("D21")) {
    const keys = createRemoteJWKSet(new URL(`${cfg.issuer}/oauth2/jwks`));
    sub = (await verifyIdToken(body.id_token, keys, { issuer: cfg.issuer, clientId: cfg.clientId, nonce: login.nonce })).sub;
  } else {
    // 悪い実装: ID トークンを確かめずに、中身を読むだけ
    sub = JSON.parse(atob(body.id_token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).sub;
  }
  sessionStorage.removeItem("login");
  store.set(sessionStorage, "session", { token: body.access_token, sub, idToken: body.id_token } satisfies Session);
}

/**
 * サインアウト（OpenID Connect の RP-Initiated Logout。D-33）。手元のセッションを消してから、認可サーバーのログインも終わらせる。
 * 認可サーバーのログインが残ると、次にログインを押したときに、前の人のまま通ってしまう。端末の passkey と写しは、人ごとに残す。
 */
function signOut() {
  const session = store.get<Session>(sessionStorage, "session");
  sessionStorage.removeItem("session");
  const q = new URLSearchParams({ client_id: cfg.clientId, post_logout_redirect_uri: `${location.origin}/` });
  if (session?.idToken) q.set("id_token_hint", session.idToken);
  location.assign(`${cfg.issuer}/connect/logout?${q}`);
}

// ---- 3. この端末の passkey と、受信箱の番号を登録する（D-26） ----

async function registerDevice(session: Session) {
  const auth = (path: string, body?: unknown) =>
    fetch(`${cfg.issuer}${path}`, {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const options = await (await auth("/passkeys/register/options")).json();
  const credential = await createPasskey(options);
  const inbox = randomB64u(16);
  const res = await auth("/passkeys/register/verify", { credential, inbox });
  if (!res.ok) throw new Error(`passkey を登録できない: ${await res.text()}`);
  store.set(localStorage, `device:${session.sub}`, { credentialId: credential.rawId, inbox } satisfies Device);
}

/**
 * この端末の passkey が、認可サーバーに登録されたまま残っているかを確かめる（認可サーバーの記憶はメモリにあり、再起動で消える）。
 * ログインの Cookie で、本人の passkey の識別子の一覧を問い合わせる。確かめられなければ、unknown を返して、今までどおり進める。
 */
async function deviceStatus(device: Device): Promise<"ok" | "missing" | "unknown"> {
  try {
    const res = await fetch(`${cfg.issuer}/passkeys/mine`, { credentials: "include", headers: { accept: "application/json" } });
    if (!res.ok) return "unknown";
    const { credentialIds } = (await res.json()) as { credentialIds: string[] };
    return credentialIds.includes(device.credentialId) ? "ok" : "missing";
  } catch {
    return "unknown";
  }
}

// ---- 4. 営業 AI エージェントとの申込み（AG-UI）。カードを積み、今のカードだけを開く（D-34） ----

const conversation = {
  threadId: crypto.randomUUID(),
  messages: [] as Message[],
  /** 直前に署名を確かめた提示（意向確認書面の案の名前を引く）。 */
  offer: undefined as Offer | undefined,
  /** 営業 AI エージェントの直前の文（D23 を外したときに、確認画面に出す）。 */
  lastText: "",
  /** まだカードに出していない、営業 AI エージェントの文。次のカードに、説明の枠で出す。 */
  pendingText: [] as string[],
  /** 今回署名した申込書の nonce（完了カードの照合で使う）。 */
  submitted: "",
  /** 申込書に署名した後で、営業 AI エージェントの番が終わるまでの間（提出の途中）。 */
  submitting: false,
  /** 走っている回を止める。 */
  abort: undefined as AbortController | undefined,
  /** 始め直すと増える。古い回のイベントと照合を捨てる。 */
  generation: 0,
};

/** 申込みの段階。呼ばれた道具から決める（質問の数は、AI 次第である）。 */
const STEPS = ["consult", "offers", "intent", "application", "reconcile"] as const;
function setStep(step: (typeof STEPS)[number]) {
  const at = STEPS.indexOf(step);
  for (const li of $("steps").querySelectorAll<HTMLElement>("li")) {
    const i = STEPS.indexOf(li.dataset.step as (typeof STEPS)[number]);
    li.classList.toggle("done", i < at);
    if (i === at) li.setAttribute("aria-current", "step");
    else li.removeAttribute("aria-current");
  }
}

/** 1 回分を走らせ、営業 AI エージェントの文をため、画面側の道具をカードにする。道具なしで番が終わったら、続きか完了のカードを出す。 */
async function run(session: Session, device: Device) {
  const generation = conversation.generation;
  const current = () => generation === conversation.generation;
  setBusy(true);
  const url = `${cfg.agentOrigin}/agui`;
  const texts = new Map<string, string>();
  const calls = new Map<string, { name: string; args: string }>();
  let called = false;
  let failed = false;
  conversation.abort = new AbortController();
  try {
    await runOnce(
      url,
      { authorization: `DPoP ${session.token}`, dpop: await dpopProof("POST", url, session.token) },
      { threadId: conversation.threadId, runId: crypto.randomUUID(), messages: conversation.messages, tools: FRONTEND_TOOLS, state: {}, context: [], forwardedProps: {} },
      (e: AgentEvent) => {
        if (!current()) return;
        if (e.type === "TEXT_MESSAGE_START") texts.set(e.messageId, "");
        if (e.type === "TEXT_MESSAGE_CONTENT") texts.set(e.messageId, (texts.get(e.messageId) ?? "") + e.delta);
        if (e.type === "TEXT_MESSAGE_END") {
          const content = texts.get(e.messageId) ?? "";
          conversation.messages.push({ id: e.messageId, role: "assistant", content });
          conversation.lastText = content;
          conversation.pendingText.push(content);
        }
        if (e.type === "TOOL_CALL_START") calls.set(e.toolCallId, { name: e.toolCallName, args: "" });
        if (e.type === "TOOL_CALL_ARGS") calls.get(e.toolCallId)!.args += e.delta;
        if (e.type === "TOOL_CALL_END") {
          called = true;
          const call = calls.get(e.toolCallId)!;
          conversation.messages.push({
            id: crypto.randomUUID(),
            role: "assistant",
            toolCalls: [{ id: e.toolCallId, type: "function", function: { name: call.name, arguments: call.args } }],
          });
          void showTool(session, device, e.toolCallId, call.name, JSON.parse(call.args)).catch(fail);
        }
        if (e.type === "RUN_ERROR") {
          failed = true;
          fail(new Error(e.message));
        }
      },
      conversation.abort.signal,
    );
  } catch (e) {
    if (!current()) return; // 始め直した: 止めた回の失敗は見せない
    conversation.submitting = false;
    if (e instanceof AgentRefused && e.status === 401) return expired(session);
    throw e;
  }
  if (!current()) return;
  conversation.submitting = false;
  if (!called && !failed) {
    if (conversation.submitted) finishCard(session, device);
    else continueCard(session, device);
  }
  setBusy(false);
}

/** 顧客の答えを tool message にして、次の回を走らせる。 */
async function answer(session: Session, device: Device, toolCallId: string, content: unknown) {
  conversation.messages.push({ id: crypto.randomUUID(), role: "tool", toolCallId, content: typeof content === "string" ? content : JSON.stringify(content) });
  clearError();
  await run(session, device);
}

async function say(session: Session, device: Device, content: string) {
  clearError();
  conversation.messages.push({ id: crypto.randomUUID(), role: "user", content });
  show("new-application");
  await run(session, device);
}

/** 同じ種類の古い道具の画面から、テストの目印を外す（目印は、最新の画面にだけ付ける）。 */
function retire(kind: string) {
  for (const old of document.querySelectorAll(`[data-tool="${kind}"] [data-testid], [data-tool="${kind}"][data-testid]`)) old.removeAttribute("data-testid");
}

/** 営業 AI エージェントの言葉の枠。保険会社の内容と見分けられるようにする。 */
function agentNote(text: string): HTMLElement {
  const div = el("div", { className: "agent" });
  div.append(el("p", { className: "frame-label", textContent: "営業 AI エージェントの説明" }));
  const body = el("div");
  body.innerHTML = markdownToHtml(text); // HTML の特別な文字を置き換えてから整える
  div.append(body);
  return div;
}

/** 新しいカードを出す。前のカードは閉じ、開けば読めるように残す。ためていた営業 AI エージェントの文は、このカードに入れる。 */
function card(kind: string, title: string): HTMLDetailsElement {
  retire(kind);
  for (const open of $("cards").querySelectorAll("details")) open.open = false;
  const box = el("details", { className: "tool", open: true });
  box.dataset.tool = kind;
  box.append(el("summary", { textContent: title }));
  for (const text of conversation.pendingText.splice(0)) box.append(agentNote(text));
  $("cards").append(box);
  box.scrollIntoView({ block: "nearest" });
  return box;
}

/** 閉じたときに読める 1 行に、答えを足す。 */
function conclude(box: HTMLElement, result: string) {
  box.querySelector("summary")!.textContent += `: ${result.length > 40 ? `${result.slice(0, 40)}…` : result}`;
}

/**
 * 自由入力。許したカードにだけ置き、送ると入力欄を消す。空のときは送らない。
 * 入力した文は、会話の記録に残るので、そのことを添える（D-32）。
 */
function freeInput(box: HTMLElement, prefix: string, label: string, placeholder: string, onSend: (text: string) => void) {
  const form = el("div", { className: "free" });
  form.append(el("label", { textContent: label }));
  const input = el("textarea", { rows: 2, placeholder }, `${prefix}-input`);
  const submit = () => {
    const text = input.value.trim();
    if (!text) return;
    form.remove();
    box.append(el("p", { className: "user", textContent: text }));
    onSend(text);
  };
  const send = el("button", { type: "button", textContent: "送る", onclick: submit }, `${prefix}-send`);
  const hint = el("p", { className: "hint", textContent: "入力した文は、監査のために記録に残ります。氏名や口座番号は書かないでください。" });
  form.append(input, send, hint);
  box.append(form);
}

/** 最初のカード: 希望を自由に書いてもらう。 */
function startCard(session: Session, device: Device) {
  const box = card("start", "ご希望をお聞かせください");
  box.append(el("p", { textContent: "営業 AI エージェントが、質問をし、案を示し、書類を用意して、署名をお願いします。署名した書類は、営業 AI エージェントが保険会社へ取り次ぎます。" }));
  freeInput(box, "free", "どのような保険をお考えですか", "例: 老後に備えて、個人年金保険を考えています。", (text) => {
    conclude(box, text);
    say(session, device, text).catch(fail);
  });
}

/** 営業 AI エージェントが、道具を使わずに番を終えたときのカード。顧客が答えられるように、自由入力を置く。 */
function continueCard(session: Session, device: Device) {
  const box = card("continue", "営業 AI エージェントから");
  freeInput(box, "free", "お答えや、続けたいことを書いてください", "例: 案を見せてください。", (text) => {
    conclude(box, text);
    say(session, device, text).catch(fail);
  });
}

/** トークン A の期限が切れたカード。送れなかった申込書の写しは、端末から消す（受信箱に未着として残さない）。 */
function expired(session: Session) {
  const nonce = conversation.submitted;
  if (nonce) {
    const copies = store.get<Copy[]>(localStorage, `copies:${session.sub}`) ?? [];
    store.set(localStorage, `copies:${session.sub}`, copies.filter((c) => c.nonce !== nonce));
    conversation.submitted = "";
  }
  const box = card("expired", "ログインし直してください");
  box.append(el("p", { textContent: "ログインの有効期間が切れました。ログインし直すと、最初からやり直します。入力した内容と署名は消え、保険会社には届いていません。" }, "expired-note"));
  box.append(el("button", { type: "button", textContent: "ログインし直す", onclick: () => startLogin().catch(fail) }, "relogin"));
  setBusy(false);
}

/** 始め直す。走っている回を止め、会話を新しくする。サーバーの古い会話は、使われなくなって捨てられる。 */
function startOver(session: Session, device: Device) {
  conversation.abort?.abort();
  Object.assign(conversation, {
    threadId: crypto.randomUUID(), messages: [], offer: undefined, lastText: "", pendingText: [], submitted: "", submitting: false, abort: undefined,
    generation: conversation.generation + 1,
  });
  clearError();
  show("new-confirm-box", false);
  show("new-application", false);
  setBusy(false);
  $("cards").replaceChildren();
  setStep("consult");
  startCard(session, device);
}

async function showTool(session: Session, device: Device, id: string, name: string, args: Record<string, any>) {
  if (name === "ask_customer") return askCustomer(session, device, id, args as { question: string; options: string[] });
  if (name === "present_offers") return presentOffers(session, device, id, args as { message?: string; offer: Offer });
  if (name === "present_intent") return presentDocument(session, device, id, "intent", args.intent as Intent);
  if (name === "present_application") return presentDocument(session, device, id, "application", args.application as Application);
  await answer(session, device, id, { error: `この画面にない道具: ${name}` });
}

function askCustomer(session: Session, device: Device, id: string, args: { question: string; options: string[] }) {
  // 質問は、どの段階でも来るので、段階の表示は動かさない
  const box = card("ask", "営業 AI エージェントからの質問");
  box.append(el("p", { textContent: args.question }));
  const reply = (text: string) => {
    for (const b of buttons) b.disabled = true;
    conclude(box, text);
    answer(session, device, id, { answer: text }).catch(fail);
  };
  const buttons = args.options.map((option, i) =>
    el("button", { type: "button", textContent: option, onclick: () => {
      buttons[i]!.classList.add("chosen");
      other.remove();
      reply(option);
    } }, `ask-option-${i}`),
  );
  box.append(...buttons);
  // 「その他」は、AI に任せず、画面が必ず足す
  freeInput(box, "ask-other", "その他（自由に入力）", "選択肢にないお考えを書いてください。", reply);
  const other = box.querySelector<HTMLElement>(".free")!;
}

async function presentOffers(session: Session, device: Device, id: string, args: { message?: string; offer: Offer }) {
  setStep("offers");
  const box = card("offers", "保険会社の案");
  box.dataset.nonce = args.offer.nonce;
  box.dataset.testid = "offers";
  if (args.message) box.append(agentNote(args.message));
  const frame = el("div", { className: "issued" });
  let offer = args.offer;
  if (enabled("D22")) {
    // 案は、保険会社の署名を確かめた中身から描く
    const keys = createLocalJWKSet((await (await fetch("/offers-jwks.json")).json()) as JSONWebKeySet);
    const v = await verifyOffer(args.offer, keys, session.sub).catch(async (e: Error) => {
      await answer(session, device, id, { declined: true, reason: "提示の署名を確かめられない" });
      throw new Error(`提示の署名を確かめられない: ${e.message}`);
    });
    if (v.tampered) {
      box.append(el("p", { className: "warning", textContent: "営業 AI エージェントが示した案が、保険会社が署名した提示と違います。署名された案だけを表示しています。" }, "offer-warning"));
    }
    offer = v.offer;
    frame.append(el("p", { className: "frame-label", textContent: "保険会社が署名した内容" }));
  } else {
    // D22 を外すと、営業 AI エージェントが運んだ案を、そのまま示す（悪い実装）
    frame.append(el("p", { className: "frame-label", textContent: "営業 AI エージェントが示した案" }));
  }
  conversation.offer = offer;
  const list = el("ul");
  for (const p of offer.offerSet.plans) {
    const li = el("li", {}, `plan-${p.id}`);
    li.append(el("strong", { textContent: p.name }), el("span", { textContent: ` 年金の年額 ${p.benefit.toLocaleString("ja-JP")} 円・月額 ${p.monthly.toLocaleString("ja-JP")} 円 ` }));
    li.append(el("button", { type: "button", textContent: "この案を選ぶ", onclick: () => {
      for (const b of list.querySelectorAll("button")) b.disabled = true;
      li.classList.add("chosen");
      conclude(box, p.name);
      answer(session, device, id, { planId: p.id, plan: p }).catch(fail);
    } }, `choose-${p.id}`));
    list.append(li);
  }
  frame.append(list);
  box.append(frame);
}

const GUIDE = {
  intent: ["意向確認書面", "署名 1/2", "営業 AI エージェントから届いた意向確認書面です。内容を確かめて、署名してください。"],
  application: ["申込書", "署名 2/2", "営業 AI エージェントから届いた申込書です。内容を確かめて、署名し、営業 AI エージェントに提出を任せます。"],
} as const;

/** 書類を示し、署名してもらう。画面は、署名する内容そのものから描く（D23）。署名すると、案内文を「署名済み」に置き換えて残す。 */
function presentDocument(session: Session, device: Device, id: string, step: "intent" | "application", doc: Intent | Application) {
  setStep(step);
  const [title, count, guide] = GUIDE[step];
  const box = card(step, `${title}（${count}）`);
  const note = el("p", { textContent: guide }, `${step}-guide`);
  box.append(note);
  const frame = el("div", { className: "issued" }, `${step}-confirm`);
  if (enabled("D23")) {
    frame.append(el("p", { className: "frame-label", textContent: "署名する内容" }));
    frame.append(table(step === "intent" ? intentRowsOf(doc as Intent, conversation.offer?.offerSet.plans ?? []) : applicationRowsOf(doc as Application), step));
  } else {
    // 悪い実装: 営業 AI エージェントの説明文を、確認画面に出す
    frame.append(el("p", { textContent: conversation.lastText }, `${step}-summary`));
  }
  box.append(frame);
  const actions = el("p");
  const sign = el("button", { type: "button", textContent: `${title}に passkey で署名する（${count}）`, onclick: async () => {
    try {
      clearError();
      const assertion = await signWithPasskey(await challengeOf(doc), cfg.rpId, device.credentialId);
      actions.remove();
      note.textContent = "✓ 署名済み";
      note.className = "signed";
      conclude(box, "署名済み");
      if (step === "application") {
        // 顧客が承認した申込みの写しを、端末に残す（事後の照合に使う）
        const copies = store.get<Copy[]>(localStorage, `copies:${session.sub}`) ?? [];
        store.set(localStorage, `copies:${session.sub}`, [...copies, doc as unknown as Copy]);
        // 完了カードで、今回の申込みだけを照合できるようにする
        conversation.submitted = doc.nonce;
        conversation.submitting = true;
      }
      await answer(session, device, id, { [step]: doc, assertion });
    } catch (e) {
      fail(e);
    }
  } }, `sign-${step}`);
  const cancel = el("button", { type: "button", textContent: "やめる", onclick: () => {
    actions.remove();
    note.textContent = "署名しませんでした";
    conclude(box, "署名しませんでした");
    answer(session, device, id, { declined: true }).catch(fail);
  } }, `cancel-${step}`);
  actions.append(sign, cancel);
  box.append(actions);
}

// ---- 5. 直送の照合（D19） ----
// 照合は 2 か所で行う。完了カードでは、今回提出した申込書だけを確かめる。「受信箱と契約」の画面では、届いた全ての契約と
// 全ての写しを突き合わせ、本人の名義で勝手に申し込まれた契約（覚えのない契約）に気付く。

type Notice = { contract: { contractId?: string; nonce: string; plan: { name: string } } };
const LABEL = { match: "一致", mismatch: "食い違い", missing: "未着", unexpected: "覚えのない契約" };

async function reconciled(session: Session, device: Device) {
  const notices = (await (await fetch(`/api/inbox/${device.inbox}`)).json()) as Notice[];
  const copies = store.get<(Copy & { plan: { name?: string } })[]>(localStorage, `copies:${session.sub}`) ?? [];
  // どの契約の行かを示す: 届いた契約の番号と案、届いていなければ写しの案
  const which = (nonce: string) => {
    const n = notices.find((x) => x.contract.nonce === nonce)?.contract;
    const c = copies.find((x) => x.nonce === nonce);
    return n ? `${n.contractId ?? ""} ${n.plan.name}` : `${c?.plan.name ?? ""}（契約の番号なし）`;
  };
  return { results: reconcile(copies, notices as never), which };
}

function rowOf(r: ReturnType<typeof reconcile>[number], which: (nonce: string) => string, prefix: string) {
  const li = el("li", { textContent: `${which(r.nonce)} — ${r.status === "match" ? LABEL.match : `${LABEL[r.status]}: ${r.diffs.join("、")}`}` }, `${prefix}-${r.nonce}`);
  li.dataset.status = r.status;
  return li;
}

/** 完了カード: 今回提出した申込書だけを照合し、結果の状態を返す。 */
async function checkSession(session: Session, device: Device): Promise<string | undefined> {
  const { results, which } = await reconciled(session, device);
  const mine = results.filter((r) => r.nonce === conversation.submitted);
  $("reconcile").replaceChildren(...mine.map((r) => rowOf(r, which, "reconcile")));
  return mine[0]?.status;
}

const RECONCILE_TRIES = 5;
const RECONCILE_WAIT_MS = 2000;

/**
 * 申込みの完了カード。押さなくても照合する。直送は少し遅れて届くので、未着なら待ち直す。
 * それでも未着なら、営業 AI エージェントが提出していないこともあるので、頼み直せるようにする。
 */
function finishCard(session: Session, device: Device) {
  setStep("reconcile");
  const generation = conversation.generation;
  const box = card("finish", "申込みの結果");
  box.append(el("p", { textContent: "保険会社から、営業 AI エージェントを通らずに直接届いた契約内容と、今回署名した申込書の写しを突き合わせます。" }));
  box.append(el("ul", { id: "reconcile" }));
  box.append(el("button", { type: "button", textContent: "もう一度照合する", onclick: () => checkSession(session, device).catch(fail) }, "check-session"));
  void (async () => {
    for (let i = 0; i < RECONCILE_TRIES; i++) {
      if (generation !== conversation.generation) return;
      if ((await checkSession(session, device)) !== "missing") return;
      await new Promise((r) => setTimeout(r, RECONCILE_WAIT_MS));
    }
    if (generation !== conversation.generation) return;
    freeInput(box, "free", "契約内容がまだ届いていません。営業 AI エージェントに伝えることがあれば書いてください", "例: 提出できたか教えてください。", (text) => {
      say(session, device, text).catch(fail);
    });
  })().catch(fail);
}

/** 「受信箱と契約」: 届いた全ての契約と、全ての写しを照合する。覚えのない契約は、警告として目立たせる。 */
async function checkInbox(session: Session, device: Device) {
  const { results, which } = await reconciled(session, device);
  const unexpected = results.filter((r) => r.status === "unexpected").length;
  $("inbox-alert").textContent = `申し込んだ覚えのない契約が ${unexpected} 件届いています。保険会社へ連絡してください。`;
  show("inbox-alert", unexpected > 0);
  $("inbox-list").replaceChildren(...results.map((r) => rowOf(r, which, "inbox")));
}

function showTab(tab: "apply" | "inbox", session: Session, device: Device) {
  show("apply", tab === "apply");
  show("inbox", tab === "inbox");
  $("tab-apply").classList.toggle("active", tab === "apply");
  $("tab-inbox").classList.toggle("active", tab === "inbox");
  if (tab === "inbox") checkInbox(session, device).catch(fail);
}

// ---- 画面の組み立て ----

async function render() {
  $("terms").replaceChildren(table(termsRowsOf(cfg.terms as { kinds: string[]; maxBenefit: number }[]), "terms"));
  const params = new URLSearchParams(location.search);
  if (location.pathname === "/callback" && params.get("code")) await finishLogin(params);
  const session = store.get<Session>(sessionStorage, "session");
  show("login", !session);
  if (!session) return;
  $("whoami").textContent = session.sub;
  show("signed-in");
  let device = store.get<Device>(localStorage, `device:${session.sub}`);
  if (device && (await deviceStatus(device)) === "missing") {
    // 認可サーバーに登録が残っていない: 端末の記録を消し、登録し直しに案内する
    localStorage.removeItem(`device:${session.sub}`);
    device = undefined;
    show("register-note");
  }
  show("register", !device);
  show("tabs", Boolean(device));
  show("apply", Boolean(device));
  if (!device) return;
  setBusy(false);
  startOver(session, device);
  // 提出の途中で始め直しても、契約になることがあるので、確かめてから始め直す
  $("new-application").onclick = () => (conversation.submitting ? show("new-confirm-box") : startOver(session, device));
  $("new-confirm").onclick = () => startOver(session, device);
  $("new-back").onclick = () => show("new-confirm-box", false);
  $("check-inbox").onclick = () => checkInbox(session, device).catch(fail);
  $("tab-apply").onclick = () => showTab("apply", session, device);
  $("tab-inbox").onclick = () => showTab("inbox", session, device);
}

$("login-button").onclick = () => startLogin().catch(fail);
$("signout-button").onclick = signOut;
$("register-button").onclick = async () => {
  try {
    await registerDevice(store.get<Session>(sessionStorage, "session")!);
    await render();
  } catch (e) {
    fail(e);
  }
};
render().catch(fail);
