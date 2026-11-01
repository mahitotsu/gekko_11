// 顧客のアプリの画面（D-18）。ブラウザで動く公開クライアントで、トークンと鍵は端末の中に置く。
// ログイン → passkey と受信箱の登録 → 相談 → 案の選択 → 確認 → 署名 → 提出 → 直送の照合、の順に進む（architecture の 3 章）。
import { createRemoteJWKSet, createLocalJWKSet, type JSONWebKeySet } from "jose";
import { reconcile, type Copy } from "../src/reconcile.ts";
import { confirmationOf, verifyIdToken, verifyOffer, type Draft, type Offer, type Plan } from "./checks.ts";
import { b64u, challengeOf, randomB64u, sha256 } from "./codec.ts";
import { loadDefenses } from "./defenses.ts";
import { createPasskey, dpopProof, signWithPasskey } from "./keys.ts";

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

function fail(e: unknown) {
  $("error").textContent = (e as Error).message ?? String(e);
  show("error");
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
  $("agent-reply").textContent = "（考えています）";
  const r = await agent<{ reply: string; offer?: Offer; engine: string }>(session, "/chat", { message });
  $("agent-reply").textContent = r.reply;
  $("engine").textContent = r.engine === "claude" ? "Claude" : "台本";
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

async function choose(planId: string) {
  const session = store.get<Session>(sessionStorage, "session")!;
  draft = await agent<Draft>(session, "/prepare", { offer: current, planId, wish: $<HTMLInputElement>("wish").value });
  const box = $("confirm-body");
  if (enabled("D23")) {
    // 確認画面は、署名する内容そのものから描く
    const table = document.createElement("table");
    for (const row of confirmationOf(draft)) {
      const tr = table.insertRow();
      tr.insertCell().textContent = row.label;
      const td = tr.insertCell();
      td.textContent = row.value;
      td.dataset.testid = `confirm-${row.key}`;
    }
    box.replaceChildren(table);
  } else {
    // 悪い実装: 営業 AI エージェントの説明文を、確認画面に出す
    const p = document.createElement("p");
    p.textContent = draft.summary;
    p.dataset.testid = "confirm-summary";
    box.replaceChildren(p);
  }
  show("confirm");
}

async function signAndSubmit(session: Session, device: Device) {
  if (!draft || !current) throw new Error("確認する申込みがない");
  const intentAssertion = await signWithPasskey(await challengeOf(draft.intent), cfg.rpId, device.credentialId);
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
  show("confirm", false);
}

// ---- 7. 直送の照合（D19） ----

async function checkInbox(session: Session, device: Device) {
  const notices = await (await fetch(`/api/inbox/${device.inbox}`)).json();
  const results = reconcile(store.get<Copy[]>(localStorage, `copies:${session.sub}`) ?? [], notices);
  const label = { match: "一致", mismatch: "食い違い", missing: "未着", unexpected: "覚えのない契約" };
  $("reconcile").replaceChildren(
    ...results.map((r) => {
      const li = document.createElement("li");
      li.dataset.testid = `reconcile-${r.nonce}`;
      li.dataset.status = r.status;
      li.textContent = `${label[r.status]}: ${r.diffs.join("、")}`;
      return li;
    }),
  );
}

// ---- 画面の組み立て ----

async function render() {
  $("terms").textContent = JSON.stringify(cfg.terms);
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
  $("sign").onclick = () => signAndSubmit(session, device).catch(fail);
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
$("cancel").onclick = () => {
  draft = undefined;
  show("confirm", false);
  $("submit-result").textContent = "申し込みをやめました";
};
render().catch(fail);
