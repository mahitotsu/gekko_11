// 顧客のアプリの画面（D-18）。ブラウザで動く公開クライアントで、トークンと鍵は端末の中に置く。
// ログインと passkey と受信箱の登録の後は、営業 AI エージェントと AG-UI で会話する（D-29）。営業 AI エージェントが、
// 質問、案の提示、意向確認書面、申込書を、画面側の道具として呼び、この画面が顧客の答え（選択と署名）を返す。
// 契約内容は、営業 AI エージェントを通らずに受信箱へ届き、端末に残した写しと照合する（architecture の 3 章）。
import { createLocalJWKSet, createRemoteJWKSet, type JSONWebKeySet } from "jose";
import type { Message } from "@ag-ui/core";
import { reconcile, type Copy } from "../src/reconcile.ts";
import { FRONTEND_TOOLS, runOnce, type AgentEvent } from "./agui.ts";
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
}

interface Device {
  credentialId: string;
  inbox: string;
}

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const show = (id: string, on = true) => $(id).toggleAttribute("hidden", !on);
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, testid?: string) => {
  const e = Object.assign(document.createElement(tag), props);
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

/** 営業 AI エージェントが考えている間は、送るボタンを止め、状態を示す。 */
function setBusy(busy: boolean) {
  $("agent-status").textContent = busy ? "営業 AI エージェントが考えています…" : "";
  $("agent-status").dataset.state = busy ? "busy" : "idle";
  $<HTMLButtonElement>("chat-send").disabled = busy;
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
  store.set(sessionStorage, "session", { token: body.access_token, sub } satisfies Session);
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

// ---- 4. 営業 AI エージェントとの会話（AG-UI） ----

const conversation = {
  threadId: crypto.randomUUID(),
  messages: [] as Message[],
  /** 直前に署名を確かめた提示（意向確認書面の案の名前を引く）。 */
  offer: undefined as Offer | undefined,
  /** 営業 AI エージェントの直前の文（D23 を外したときに、確認画面に出す）。 */
  lastText: "",
  /** 今回署名した申込書の nonce（会話の最後の照合で使う）。 */
  submitted: "",
};

/** 1 回分を走らせ、営業 AI エージェントの文と、画面側の道具の呼び出しを、会話の欄に足していく。 */
async function run(session: Session, device: Device) {
  setBusy(true);
  const url = `${cfg.agentOrigin}/agui`;
  const texts = new Map<string, string>();
  const calls = new Map<string, { name: string; args: string }>();
  await runOnce(
    url,
    { authorization: `DPoP ${session.token}`, dpop: await dpopProof("POST", url, session.token) },
    { threadId: conversation.threadId, runId: crypto.randomUUID(), messages: conversation.messages, tools: FRONTEND_TOOLS, state: {}, context: [], forwardedProps: {} },
    (e: AgentEvent) => {
      if (e.type === "TEXT_MESSAGE_START") texts.set(e.messageId, "");
      if (e.type === "TEXT_MESSAGE_CONTENT") texts.set(e.messageId, (texts.get(e.messageId) ?? "") + e.delta);
      if (e.type === "TEXT_MESSAGE_END") {
        const content = texts.get(e.messageId) ?? "";
        conversation.messages.push({ id: e.messageId, role: "assistant", content });
        conversation.lastText = content;
        addAgentText(content);
      }
      if (e.type === "TOOL_CALL_START") calls.set(e.toolCallId, { name: e.toolCallName, args: "" });
      if (e.type === "TOOL_CALL_ARGS") calls.get(e.toolCallId)!.args += e.delta;
      if (e.type === "TOOL_CALL_END") {
        const call = calls.get(e.toolCallId)!;
        conversation.messages.push({
          id: crypto.randomUUID(),
          role: "assistant",
          toolCalls: [{ id: e.toolCallId, type: "function", function: { name: call.name, arguments: call.args } }],
        });
        void showTool(session, device, e.toolCallId, call.name, JSON.parse(call.args)).catch(fail);
      }
      if (e.type === "RUN_ERROR") fail(new Error(e.message));
    },
  );
  setBusy(false);
}

/** 顧客の答えを tool message にして、次の回を走らせる。 */
async function answer(session: Session, device: Device, toolCallId: string, content: unknown) {
  conversation.messages.push({ id: crypto.randomUUID(), role: "tool", toolCallId, content: typeof content === "string" ? content : JSON.stringify(content) });
  clearError();
  await run(session, device);
}

async function say(session: Session, device: Device) {
  const content = $<HTMLTextAreaElement>("chat-input").value.trim();
  if (!content) return;
  clearError();
  conversation.messages.push({ id: crypto.randomUUID(), role: "user", content });
  addItem(el("p", { className: "user", textContent: content }));
  await run(session, device);
}

function addItem(node: HTMLElement) {
  $("conversation").append(node);
  node.scrollIntoView({ block: "nearest" });
}

function addAgentText(text: string) {
  const div = el("div", { className: "agent" });
  div.innerHTML = markdownToHtml(text); // HTML の特別な文字を置き換えてから整える
  addItem(div);
}

/** 同じ種類の古い道具の画面から、テストの目印を外す（目印は、最新の画面にだけ付ける）。 */
function retire(kind: string) {
  for (const old of document.querySelectorAll(`[data-tool="${kind}"] [data-testid], [data-tool="${kind}"][data-testid]`)) old.removeAttribute("data-testid");
}

function card(kind: string, title: string): HTMLElement {
  retire(kind);
  const box = el("section", { className: "tool" });
  box.dataset.tool = kind;
  box.append(el("h3", { textContent: title }));
  addItem(box);
  return box;
}

async function showTool(session: Session, device: Device, id: string, name: string, args: Record<string, any>) {
  if (name === "ask_customer") return askCustomer(session, device, id, args as { question: string; options: string[] });
  if (name === "present_offers") return presentOffers(session, device, id, args as { message?: string; offer: Offer });
  if (name === "present_intent") return presentDocument(session, device, id, "intent", args.intent as Intent);
  if (name === "present_application") return presentDocument(session, device, id, "application", args.application as Application);
  await answer(session, device, id, { error: `この画面にない道具: ${name}` });
}

function askCustomer(session: Session, device: Device, id: string, args: { question: string; options: string[] }) {
  const box = card("ask", "営業 AI エージェントからの質問");
  box.append(el("p", { textContent: args.question }));
  const buttons = args.options.map((option, i) =>
    el("button", { type: "button", textContent: option, onclick: () => {
      for (const b of buttons) b.disabled = true;
      buttons[i]!.classList.add("chosen");
      answer(session, device, id, option).catch(fail);
    } }, `ask-option-${i}`),
  );
  box.append(...buttons);
}

async function presentOffers(session: Session, device: Device, id: string, args: { message?: string; offer: Offer }) {
  const box = card("offers", "保険会社の案");
  box.dataset.nonce = args.offer.nonce;
  box.dataset.testid = "offers";
  if (args.message) box.append(el("p", { textContent: args.message }));
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
  }
  // D22 を外すと、営業 AI エージェントが運んだ案を、そのまま示す（悪い実装）
  conversation.offer = offer;
  const list = el("ul");
  for (const p of offer.offerSet.plans) {
    const li = el("li", {}, `plan-${p.id}`);
    li.append(el("strong", { textContent: p.name }), el("span", { textContent: ` 年金の年額 ${p.benefit.toLocaleString("ja-JP")} 円・月額 ${p.monthly.toLocaleString("ja-JP")} 円 ` }));
    li.append(el("button", { type: "button", textContent: "この案を選ぶ", onclick: () => {
      for (const b of list.querySelectorAll("button")) b.disabled = true;
      li.classList.add("chosen");
      answer(session, device, id, { planId: p.id, plan: p }).catch(fail);
    } }, `choose-${p.id}`));
    list.append(li);
  }
  box.append(list);
}

const GUIDE = {
  intent: ["意向確認書面", "署名 1/2", "営業 AI エージェントから届いた意向確認書面です。内容を確かめて、署名してください。"],
  application: ["申込書", "署名 2/2", "営業 AI エージェントから届いた申込書です。内容を確かめて、署名し、営業 AI エージェントに提出を任せます。"],
} as const;

/** 書類を示し、署名してもらう。画面は、署名する内容そのものから描く（D23）。署名すると、案内文を「署名済み」に置き換えて残す。 */
function presentDocument(session: Session, device: Device, id: string, step: "intent" | "application", doc: Intent | Application) {
  const [title, count, guide] = GUIDE[step];
  const box = card(step, `${title}（${count}）`);
  const note = el("p", { textContent: guide }, `${step}-guide`);
  box.append(note);
  if (enabled("D23")) {
    box.append(table(step === "intent" ? intentRowsOf(doc as Intent, conversation.offer?.offerSet.plans ?? []) : applicationRowsOf(doc as Application), step));
  } else {
    // 悪い実装: 営業 AI エージェントの説明文を、確認画面に出す
    box.append(el("p", { textContent: conversation.lastText }, `${step}-summary`));
  }
  box.dataset.testid = `${step}-confirm`;
  const actions = el("p");
  const sign = el("button", { type: "button", textContent: `${title}に passkey で署名する（${count}）`, onclick: async () => {
    try {
      clearError();
      const assertion = await signWithPasskey(await challengeOf(doc), cfg.rpId, device.credentialId);
      actions.remove();
      note.textContent = "✓ 署名済み";
      note.className = "signed";
      if (step === "application") {
        // 顧客が承認した申込みの写しを、端末に残す（事後の照合に使う）
        const copies = store.get<Copy[]>(localStorage, `copies:${session.sub}`) ?? [];
        store.set(localStorage, `copies:${session.sub}`, [...copies, doc as unknown as Copy]);
        // 会話の最後で、今回の申込みだけを照合できるようにする
        conversation.submitted = doc.nonce;
        $("reconcile").replaceChildren();
        show("session-check");
      }
      await answer(session, device, id, { [step]: doc, assertion });
    } catch (e) {
      fail(e);
    }
  } }, `sign-${step}`);
  const cancel = el("button", { type: "button", textContent: "やめる", onclick: () => {
    actions.remove();
    note.textContent = "署名しませんでした";
    answer(session, device, id, { declined: true }).catch(fail);
  } }, `cancel-${step}`);
  actions.append(sign, cancel);
  box.append(actions);
}

// ---- 5. 直送の照合（D19） ----
// 照合は 2 か所で行う。会話の最後では、今回提出した申込書だけを確かめる。「受信箱と契約」の画面では、届いた全ての契約と
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

/** 会話の最後: 今回提出した申込書だけを照合する。 */
async function checkSession(session: Session, device: Device) {
  const { results, which } = await reconciled(session, device);
  const mine = results.filter((r) => r.nonce === conversation.submitted);
  $("reconcile").replaceChildren(...mine.map((r) => rowOf(r, which, "reconcile")));
}

/** 「受信箱と契約」: 届いた全ての契約と、全ての写しを照合する。覚えのない契約は、警告として目立たせる。 */
async function checkInbox(session: Session, device: Device) {
  const { results, which } = await reconciled(session, device);
  const unexpected = results.filter((r) => r.status === "unexpected").length;
  $("inbox-alert").textContent = `申し込んだ覚えのない契約が ${unexpected} 件届いています。保険会社へ連絡してください。`;
  show("inbox-alert", unexpected > 0);
  $("inbox-list").replaceChildren(...results.map((r) => rowOf(r, which, "inbox")));
}

function showTab(tab: "chat" | "inbox", session: Session, device: Device) {
  show("chat", tab === "chat");
  show("inbox", tab === "inbox");
  $("tab-chat").classList.toggle("active", tab === "chat");
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
  show("chat", Boolean(device));
  if (!device) return;
  setBusy(false);
  $("chat-send").onclick = () => say(session, device).catch(fail);
  $("check-session").onclick = () => checkSession(session, device).catch(fail);
  $("check-inbox").onclick = () => checkInbox(session, device).catch(fail);
  $("tab-chat").onclick = () => showTab("chat", session, device);
  $("tab-inbox").onclick = () => showTab("inbox", session, device);
}

$("login-button").onclick = () => startLogin().catch(fail);
$("register-button").onclick = async () => {
  try {
    await registerDevice(store.get<Session>(sessionStorage, "session")!);
    await render();
  } catch (e) {
    fail(e);
  }
};
render().catch(fail);
