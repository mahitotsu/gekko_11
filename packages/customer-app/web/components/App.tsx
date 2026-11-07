// 顧客のアプリの画面（D-18）。ブラウザで動く公開クライアントで、トークンと鍵は端末の中に置く。
// ログインと passkey と受信箱の登録の後は、営業 AI エージェントと AG-UI でやりとりし、カードを積んで進む（D-29、D-34）。営業 AI エージェントが、
// 質問、案の提示、意向確認書面、申込書を、画面側の道具として呼び、この画面が顧客の答え（選択と署名）を返す。
// 契約内容は、営業 AI エージェントを通らずに受信箱へ届き、端末に残した写しと照合する（architecture の 3 章）。
import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import type { User } from "oidc-client-ts";
import type { Auth, Config, Session } from "../auth.ts";
import { termsRowsOf } from "../checks.ts";
import { randomB64u } from "../codec.ts";
import { initialState, reducer, type ReconcileRow, type Step } from "../conversation.ts";
import { createController, reconciled, type Device } from "../controller.ts";
import { createPasskey } from "../passkey.ts";
import { Cards, RowsTable } from "./Cards.tsx";

const STEPS: { step: Step; label: string }[] = [
  { step: "consult", label: "相談" },
  { step: "offers", label: "案" },
  { step: "intent", label: "意向確認" },
  { step: "application", label: "申込み" },
  { step: "reconcile", label: "照合" },
];

interface Props {
  cfg: Config;
  auth: Auth;
  enabled: (id: string) => boolean;
}

const failText = (e: unknown) => {
  const err = e as Error;
  return err?.name === "NotAllowedError" ? "passkey の操作が取り消されたか、時間切れになりました。もう一度ボタンを押してください。" : (err?.message ?? String(e));
};

/** 認可サーバーの passkey の受け口を、P と DPoP の proof で呼ぶ（D-37）。 */
async function callPasskeys(cfg: Config, auth: Auth, user: User, method: "GET" | "POST", path: string, body?: unknown) {
  const url = `${cfg.authOrigin}${path}`;
  return fetch(url, {
    method,
    headers: {
      accept: "application/json",
      authorization: `DPoP ${user.access_token}`,
      dpop: await auth.passkeyProof(url, method, user),
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/**
 * この端末の passkey が、認可サーバーに登録されたまま残っているかを確かめる（認可サーバーの記憶はメモリにあり、再起動で消える）。
 * P で、本人の passkey の識別子の一覧を問い合わせる。確かめられなければ、unknown を返して、今までどおり進める。
 */
async function deviceStatus(cfg: Config, auth: Auth, device: Device): Promise<"ok" | "missing" | "unknown"> {
  const user = await auth.passkeyUser();
  if (!user) return "unknown";
  try {
    const res = await callPasskeys(cfg, auth, user, "GET", "/passkeys/mine");
    if (!res.ok) return "unknown";
    const { credentialIds } = (await res.json()) as { credentialIds: string[] };
    return credentialIds.includes(device.credentialId) ? "ok" : "missing";
  } catch {
    return "unknown";
  }
}

function Apply({ cfg, auth, enabled, session, device, hidden, onError }: Props & { session: Session; device: Device; hidden: boolean; onError: (message?: string) => void }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  // 非同期の処理の途中でも、最新の状態を読む。dispatch の結果を、描画を待たずに反映する
  const latest = useRef(state);
  const send = useMemo(
    () => (action: Parameters<typeof reducer>[1]) => {
      latest.current = reducer(latest.current, action);
      dispatch(action);
    },
    [],
  );
  const controller = useMemo(() => createController({ cfg, auth, enabled, session, device, dispatch: send, state: () => latest.current }), [cfg, auth, enabled, session, device, send]);
  useEffect(() => controller.startOver(), [controller]);
  useEffect(() => onError(state.error), [state.error, onError]);
  const at = STEPS.findIndex((s) => s.step === state.step);
  return (
    <section id="apply" hidden={hidden}>
      <ol id="steps" data-testid="steps">
        {STEPS.map((s, i) => (
          <li key={s.step} data-step={s.step} className={i < at ? "done" : undefined} aria-current={i === at ? "step" : undefined}>{s.label}</li>
        ))}
      </ol>
      <Cards controller={controller} state={state} auth={auth} enabled={enabled} />
      <p id="agent-status" data-testid="agent-status" data-state={state.busy ? "busy" : "idle"}>{state.busy ? "営業 AI エージェントが考えています…" : ""}</p>
      <div id="new-confirm-box" className="confirm" data-testid="new-confirm-box" hidden={!state.confirmNew}>
        <p>申込書に署名した後で、営業 AI エージェントが提出を進めています。ここで始め直しても、契約になることがあります。結果は「受信箱と契約」で確かめてください。</p>
        <button id="new-confirm" data-testid="new-confirm" type="button" onClick={() => controller.startOver()}>それでも始め直す</button>
        <button id="new-back" data-testid="new-back" type="button" onClick={() => send({ type: "confirmNew", on: false })}>戻る</button>
      </div>
      <p>
        {/* 提出の途中で始め直しても、契約になることがあるので、確かめてから始め直す */}
        <button id="new-application" data-testid="new-application" type="button" hidden={!state.started} onClick={() => (state.submitting ? send({ type: "confirmNew", on: true }) : controller.startOver())}>新しい申し込み</button>
      </p>
    </section>
  );
}

/** 「受信箱と契約」: 届いた全ての契約と、全ての写しを照合する。覚えのない契約は、警告として目立たせる。 */
function Inbox({ session, device, hidden, visible, onError }: { session: Session; device: Device; hidden: boolean; visible: boolean; onError: (message?: string) => void }) {
  const [rows, setRows] = useState<ReconcileRow[]>([]);
  const check = () => reconciled(session, device).then(setRows).catch((e) => onError(failText(e)));
  useEffect(() => {
    if (visible) void check();
    // 画面を開いたときに照合する
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible]);
  const unexpected = rows.filter((r) => r.status === "unexpected").length;
  return (
    <section id="inbox" hidden={hidden}>
      <h2>受信箱と契約</h2>
      <p>保険会社から直接届いた全ての契約内容を、この端末に残した申込みの写しと突き合わせます。申し込んだ覚えのない契約が届いていたら、保険会社へ連絡してください。</p>
      <button id="check-inbox" data-testid="check-inbox" type="button" onClick={() => void check()}>最新の受信箱を照合する</button>
      <p id="inbox-alert" className="alert" data-testid="inbox-alert" hidden={unexpected === 0}>{`申し込んだ覚えのない契約が ${unexpected} 件届いています。保険会社へ連絡してください。`}</p>
      <ul id="inbox-list">
        {rows.map((r) => <li key={r.nonce} data-status={r.status} data-testid={`inbox-${r.nonce}`}>{r.text}</li>)}
      </ul>
    </section>
  );
}

export function App({ cfg, auth, enabled }: Props) {
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState<Session>();
  const [device, setDevice] = useState<Device>();
  const [missing, setMissing] = useState(false);
  const [tab, setTab] = useState<"apply" | "inbox">("apply");
  const [error, setError] = useState<string>();
  const fail = (e: unknown) => setError(failText(e));

  useEffect(() => {
    void (async () => {
      const params = new URLSearchParams(location.search);
      if (location.pathname === "/callback" && (params.get("code") || params.get("error")) && (await auth.finishLogin())) return;
      const current = await auth.session();
      setSession(current);
      setReady(true);
      if (!current) return;
      const saved = localStorage.getItem(`device:${current.sub}`);
      const known = saved ? (JSON.parse(saved) as Device) : undefined;
      if (known && (await deviceStatus(cfg, auth, known)) === "missing") {
        // 認可サーバーに登録が残っていない: 端末の記録を消し、登録し直しに案内する
        localStorage.removeItem(`device:${current.sub}`);
        setMissing(true);
        return;
      }
      setDevice(known);
    })().catch((e) => {
      setReady(true);
      fail(e);
    });
    // 画面を開いたときに 1 度だけ行う
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function registerDevice() {
    try {
      // P は 5 分で切れる。切れていたら受け取り直し、戻ったところで、もう一度押してもらう
      const user = await auth.passkeyUser();
      if (!user) return await auth.startPasskeyToken();
      const post = (path: string, body?: unknown) => callPasskeys(cfg, auth, user, "POST", path, body);
      const options = await (await post("/passkeys/register/options")).json();
      const credential = await createPasskey(options);
      const inbox = randomB64u(16);
      const res = await post("/passkeys/register/verify", { credential, inbox });
      if (!res.ok) throw new Error(`passkey を登録できない: ${await res.text()}`);
      const next = { credentialId: credential.rawId, inbox };
      localStorage.setItem(`device:${session!.sub}`, JSON.stringify(next));
      setMissing(false);
      setDevice(next);
    } catch (e) {
      fail(e);
    }
  }

  return (
    <>
      <h1>教材保険会社 顧客のアプリ</h1>
      <p id="error" data-testid="error" hidden={!error}>{error}</p>
      {ready && !session && (
        <section id="login">
          <p>営業 AI エージェントに、次の範囲で申込みの取り次ぎを任せます（取決め）。</p>
          <div id="terms" data-testid="terms">
            <RowsTable rows={termsRowsOf(cfg.terms as { kinds: string[]; maxBenefit: number }[])} prefix="terms" />
          </div>
          <button id="login-button" data-testid="login" type="button" onClick={() => auth.startLogin().catch(fail)}>同意して保険会社にログインする</button>
        </section>
      )}
      {session && (
        <section id="signed-in">
          <p>ログイン中: <strong id="whoami" data-testid="whoami">{session.sub}</strong> <button id="signout-button" data-testid="signout" type="button" onClick={() => auth.signOut().catch(fail)}>サインアウト</button></p>
        </section>
      )}
      {session && !device && (
        <section id="register">
          <p id="register-note" className="warning" data-testid="register-note" hidden={!missing}>この端末の登録が、保険会社に見つかりませんでした（保険会社のシステムが入れ替わった可能性があります）。もう一度登録してください。</p>
          <p>この端末に、署名に使う passkey と、契約内容が届く受信箱を登録します。</p>
          <button id="register-button" data-testid="register-passkey" type="button" onClick={() => void registerDevice()}>passkey を登録する</button>
        </section>
      )}
      {session && device && (
        <>
          <nav id="tabs">
            <button id="tab-apply" data-testid="tab-apply" type="button" className={tab === "apply" ? "tab active" : "tab"} onClick={() => setTab("apply")}>申し込む</button>
            <button id="tab-inbox" data-testid="tab-inbox" type="button" className={tab === "inbox" ? "tab active" : "tab"} onClick={() => setTab("inbox")}>受信箱と契約</button>
          </nav>
          <Apply cfg={cfg} auth={auth} enabled={enabled} session={session} device={device} hidden={tab !== "apply"} onError={setError} />
          <Inbox session={session} device={device} hidden={tab !== "inbox"} visible={tab === "inbox"} onError={setError} />
        </>
      )}
    </>
  );
}
