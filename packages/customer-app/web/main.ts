// 顧客のアプリの画面（D-18）。ブラウザで動く公開クライアントで、トークンと鍵は端末の中に置く。
// ログイン → passkey と受信箱の登録 → 相談 → 案の選択 → 確認 → 署名 → 提出 → 直送の照合、の順に進む（architecture の 3 章）。
import { createRemoteJWKSet, createLocalJWKSet, type JSONWebKeySet } from "jose";
import { reconcile, type Copy } from "../src/reconcile.ts";
import { applicationRowsOf, intentRowsOf, termsRowsOf, verifyIdToken, verifyOffer, type Draft, type Offer, type Plan, type Row } from "./checks.ts";
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
  if ($("agent-reply").textContent === "（考えています）") $("agent-reply").textContent = "（答えを受け取れませんでした）";
}

const clearError = () => show("error", false);

function table(rows: Row[], prefix: string): HTMLTableElement {
  const t = document.createElement("table");
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
  const challenge = b64u(await sha256(login.verifier));
  const q = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    scope: "openid apply",
    redirect_uri: redirectUri,
    state: login.state,
    nonce: login.nonce,
    code_challenge: challenge,
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

// ---- 4〜6. 営業 AI エージェントとのやりとり（A と DPoP の proof を付ける） ----

async function agent<T>(session: Session, path: string, body: unknown): Promise<T> {
  const url = `${cfg.agentOrigin}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `DPoP ${session.token}`, dpop: await dpopProof("POST", url, session.token) },
    body: JSON.stringify(body),
  });
  const out = (await res.json().catch(() => ({}))) as T & { error?: string };
  if (!res.ok) throw new Error(`営業 AI エージェントが断った: ${out.error ?? JSON.stringify(out)}`);
  return out;
}

let current: Offer | undefined;
let draft: Draft | undefined;

async function chat(session: Session) {
  const message = $<HTMLTextAreaElement>("chat-input").value;
  clearError();
  $("agent-reply").textContent = "（考えています）";
  const r = await agent<{ reply: string; offer?: Offer; engine: string }>(session, "/chat", { message });
  // 説明文は、HTML の特別な文字を置き換えてから、表と箇条書きを整える
  $("agent-reply").innerHTML = markdownToHtml(r.reply);
  $("engine").textContent = `（${r.engine === "claude" ? "Claude" : "台本"}）`;
  show("offer-warning", false);
  if (!r.offer?.offerJws) return;
  if (enabled("D22")) {
    // 案は、保険会社の署名を確かめた中身から描く
    const keys = createLocalJWKSet((await (await fetch("/offers-jwks.json")).json()) as JSONWebKeySet);
    const v = await verifyOffer(r.offer, keys, session.sub).catch((e: Error) => {
      throw new Error(`提示の署名を確かめられない: ${e.message}`);
    });
    if (v.tampered) {
      $("offer-warning").textContent = "営業 AI エージェントが示した案が、保険会社が署名した提示と違います。署名された案だけを表示しています。";
      show("offer-warning");
    }
    current = v.offer;
  } else {
    // 悪い実装: 営業 AI エージェントが運んだ案を、そのまま示す
    current = r.offer;
  }
  renderPlans(current.offerSet.plans);
}

function renderPlans(plans: Plan[]) {
  const list = $("plans");
  list.replaceChildren(
    ...plans.map((p) => {
      const li = document.createElement("li");
      li.dataset.testid = `plan-${p.id}`;
      li.innerHTML = `<strong></strong><span></span><button type="button">この案を選ぶ</button>`;
      li.querySelector("strong")!.textContent = p.name;
      li.querySelector("span")!.textContent = ` 年金の年額 ${p.benefit.toLocaleString("ja-JP")} 円・月額 ${p.monthly.toLocaleString("ja-JP")} 円 `;
      const button = li.querySelector("button")!;
      button.dataset.testid = `choose-${p.id}`;
      button.onclick = () => choose(p.id).catch(fail);
      return li;
    }),
  );
  show("offer");
}

let intentAssertion: Awaited<ReturnType<typeof signWithPasskey>> | undefined;

const GUIDE = { intent: "選んだ案と意向を確かめて、署名してください。", application: "申し込む内容を確かめて、署名してください。" };

/** 書類の署名が済んだら、案内文を「署名済み」に置き換え、署名とやめるのボタンを隠す。 */
function setSigned(step: "intent" | "application", signed: boolean) {
  $(`${step}-guide`).textContent = signed ? "✓ 署名済み" : GUIDE[step];
  $(`${step}-guide`).classList.toggle("signed", signed);
  show(`${step}-actions`, !signed);
}

/** 署名の画面に、署名する内容（D23）か、営業 AI エージェントの説明文（D23 を外したとき）を描く。 */
function drawSigning(box: string, rows: Row[], prefix: string) {
  if (enabled("D23")) {
    $(box).replaceChildren(table(rows, prefix));
  } else {
    // 悪い実装: 営業 AI エージェントの説明文を、確認画面に出す
    const p = document.createElement("p");
    p.textContent = draft!.summary;
    p.dataset.testid = `${prefix}-summary`;
    $(box).replaceChildren(p);
  }
}

async function choose(planId: string) {
  const session = store.get<Session>(sessionStorage, "session")!;
  clearError();
  draft = await agent<Draft>(session, "/prepare", { offer: current, planId, wish: $<HTMLInputElement>("wish").value });
  intentAssertion = undefined;
  // 署名の 1/2: 意向確認書面
  drawSigning("intent-body", intentRowsOf(draft, current!.offerSet.plans), "intent");
  setSigned("intent", false);
  show("application-confirm", false);
  show("intent-confirm");
  $("submit-result").textContent = "";
}

async function signIntent(device: Device) {
  if (!draft) throw new Error("確認する意向確認書面がない");
  clearError();
  intentAssertion = await signWithPasskey(await challengeOf(draft.intent), cfg.rpId, device.credentialId);
  // 署名の 2/2: 申込書。署名を終えた意向確認書面は、署名済みとして上に残す（手続きが進んだことが見える）
  setSigned("intent", true);
  drawSigning("application-body", applicationRowsOf(draft), "application");
  setSigned("application", false);
  show("application-confirm");
}

async function signApplication(session: Session, device: Device) {
  if (!draft || !current || !intentAssertion) throw new Error("確認する申込書がない");
  clearError();
  const application = { ...draft.application, intentSignature: intentAssertion.response.signature };
  const assertion = await signWithPasskey(await challengeOf(application), cfg.rpId, device.credentialId);
  const r = await agent<{ contract?: { contractId: string } }>(session, "/submit", {
    intent: draft.intent,
    intentAssertion,
    application,
    assertion,
    offerJws: current.offerJws,
    offerSet: current.offerSet,
  });
  // 署名済みの申込みの写しを、端末に残す（事後の照合に使う）
  const copies = store.get<Copy[]>(localStorage, `copies:${session.sub}`) ?? [];
  store.set(localStorage, `copies:${session.sub}`, [...copies, application]);
  $("submit-result").textContent = `申し込みました（${r.contract?.contractId ?? ""}）`;
  setSigned("application", true);
}

// ---- 7. 直送の照合（D19） ----

async function checkInbox(session: Session, device: Device) {
  type Notice = { contract: { contractId?: string; nonce: string; plan: { name: string } } };
  const notices = (await (await fetch(`/api/inbox/${device.inbox}`)).json()) as Notice[];
  const copies = store.get<(Copy & { plan: { name?: string } })[]>(localStorage, `copies:${session.sub}`) ?? [];
  const results = reconcile(copies, notices as never);
  // どの契約の行かを示す: 届いた契約の番号と案、届いていなければ写しの案
  const which = (nonce: string) => {
    const n = notices.find((x) => x.contract.nonce === nonce)?.contract;
    const c = copies.find((x) => x.nonce === nonce);
    return n ? `${n.contractId ?? ""} ${n.plan.name}` : `${c?.plan.name ?? ""}（契約の番号なし）`;
  };
  const label = { match: "一致", mismatch: "食い違い", missing: "未着", unexpected: "覚えのない契約" };
  $("reconcile").replaceChildren(
    ...results.map((r) => {
      const li = document.createElement("li");
      li.dataset.testid = `reconcile-${r.nonce}`;
      li.dataset.status = r.status;
      li.textContent = `${which(r.nonce)} — ${r.status === "match" ? label.match : `${label[r.status]}: ${r.diffs.join("、")}`}`;
      return li;
    }),
  );
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
  const device = store.get<Device>(localStorage, `device:${session.sub}`);
  show("register", !device);
  show("chat", Boolean(device));
  if (!device) return;
  $("chat-send").onclick = () => chat(session).catch(fail);
  $("sign-intent").onclick = () => signIntent(device).catch(fail);
  $("sign-application").onclick = () => signApplication(session, device).catch(fail);
  $("check-inbox").onclick = () => checkInbox(session, device).catch(fail);
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
for (const id of ["cancel-intent", "cancel-application"]) {
  $(id).onclick = () => {
    draft = undefined;
    intentAssertion = undefined;
    show("intent-confirm", false);
    show("application-confirm", false);
    $("submit-result").textContent = "申し込みをやめました";
  };
}
render().catch(fail);
