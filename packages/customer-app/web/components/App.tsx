// 顧客のアプリの画面（D-40）。トークンと鍵は BFF が持ち、画面は持たない（D-41）。
// ログインの後は、営業 AI エージェントと AG-UI でやりとりし、カードを積んで進む（D-29、D-34）。営業 AI エージェントが、
// 質問、案の提示、意向確認書面、申込書を、画面側の道具として呼び、この画面が顧客の答え（選択と署名）を返す。
// 契約内容は、営業 AI エージェントを通らずに受信箱へ届き、端末に残した写しと照合する（architecture の 3 章）。
import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import { device as thisDevice, usedPasskey, type Auth, type Config, type Device, type Session } from "../auth.ts";
import { termsRowsOf } from "../checks.ts";
import { initialState, reducer, type ReconcileRow, type Step } from "../conversation.ts";
import { createController, reconciled } from "../controller.ts";
import { signalAccepted } from "../passkey.ts";
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

function Apply(props: Props & { session: Session; device: Device; hidden: boolean; onError: (message?: string) => void; onSigning: (signing: boolean) => void }) {
  const { cfg, auth, enabled, session, device, hidden, onError, onSigning } = props;
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
  const controller = useMemo(() => createController({ cfg, enabled, session, device, dispatch: send, state: () => latest.current }), [cfg, enabled, session, device, send]);
  useEffect(() => controller.startOver(), [controller]);
  useEffect(() => onError(state.error), [state.error, onError]);
  useEffect(() => onSigning(state.signing), [state.signing, onSigning]);
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
        <button id="new-application" data-testid="new-application" type="button" hidden={!state.started} disabled={state.signing} onClick={() => (state.submitting ? send({ type: "confirmNew", on: true }) : controller.startOver())}>新しい申し込み</button>
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

/**
 * 「パスキー」の欄（D-43）。保険会社にある本人の passkey の一覧と、作成と削除。
 * この端末に passkey があるかは、ブラウザが教えないので、一覧は保険会社にあるものだけを示す。
 * 使えなくなった端末の passkey を見分けられるよう、作った環境と日時（名前）と、この端末で署名に使えたものの印を出す。
 */
function Passkeys({ session, auth, hidden }: { session: Session; auth: Auth; hidden: boolean }) {
  const list = session.passkeys?.passkeys;
  const used = usedPasskey.get(session.sub);
  return (
    <section id="passkeys" data-testid="passkeys" hidden={hidden}>
      <p>パスキーは、ログインと、申込みの署名に使います。保険会社に登録されているパスキーは、次のとおりです。</p>
      {!list && <p data-testid="passkeys-unknown">保険会社から、パスキーの一覧を読めませんでした。</p>}
      {list && list.length === 0 && <p data-testid="passkeys-none">まだありません。</p>}
      {list && list.length > 0 && (
        <ul data-testid="passkeys-list">
          {list.map((k) => (
            <li key={k.id} data-testid="passkey-item" data-used={k.id === used ? "true" : undefined}>
              {k.label || `名前のないパスキー（${new Date(k.created).toLocaleString("ja-JP")} に作成）`}
              {k.id === used && <strong>（この端末で使ったパスキー）</strong>}{" "}
              <button data-testid="delete-passkey" type="button" onClick={() => auth.deletePasskey(k.ref)}>消す</button>
            </li>
          ))}
        </ul>
      )}
      <p className="hint">
        なくした端末や、使えなくなったパスキーは、「消す」で保険会社から消してください。消す前に、保険会社のログインの画面で確かめます。
        「この端末で使ったパスキー」の印は、この端末で申込みに署名したときに付きます。
      </p>
      <p className="hint">
        この端末でパスキーが使えないとき（ログインで「unknown user」と出る、署名できない）は、作ってください。この端末にまだ使えるパスキーがあるときは、作れません。
        作ると、この端末の使えなくなったパスキーは置き換わります（端末によっては、置き換えずに追加されます）。
      </p>
      <button data-testid="add-passkey" type="button" onClick={() => auth.startLogin(true)}>パスキーを作る</button>
    </section>
  );
}

export function App({ cfg, auth, enabled }: Props) {
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState<Session>();
  const [device, setDevice] = useState<Device>();
  const [tab, setTab] = useState<"apply" | "inbox" | "passkeys">("apply");
  // 保険会社に本人の passkey がないときに、作成を促す（D-43）。「後で」で閉じる
  const [prompt, setPrompt] = useState(false);
  const [error, setError] = useState<string>();
  // ログインのときの知らせ（ログインの失敗、受信箱と passkey の登録）。申込みのカードは、表示のたびに自分のエラーで error を上書きするので、分けて持つ
  const [notice, setNotice] = useState<string>();
  // 誤りではない知らせ（passkey を作った、消した）
  const [info, setInfo] = useState<string>();
  // passkey の署名を待っている間。ページを離れると署名の要求が壊れるので、サインアウトを止める
  const [signing, setSigning] = useState(false);

  useEffect(() => {
    void (async () => {
      // 認可コードは BFF が受け取る。失敗したときだけ、理由を付けて画面へ戻す
      const params = new URLSearchParams(location.search);
      const loginError = params.get("login_error");
      if (location.search) history.replaceState(null, "", "/");
      if (loginError) setNotice(loginError);
      const current = await auth.session();
      setSession(current);
      setReady(true);
      if (!current) return;
      if (!current.inboxRegistered) setNotice("この端末の受信箱を、保険会社に登録できませんでした。ログインし直してください。");
      else if (current.passkeyAction) {
        const { action, status } = current.passkeyAction;
        if (action === "create" && status === "success") setInfo("パスキーを作りました。");
        if (action === "create" && status !== "success") {
          setNotice("パスキーを作れませんでした。取り消したときのほか、この端末にまだ使えるパスキーがあるときも、作れません。「パスキー」の欄から、もう一度作れます。");
        }
        if (action === "delete" && status === "success") setInfo("パスキーを消しました。");
        if (action === "delete" && status === "error") setNotice("パスキーを消せませんでした。");
      }
      if (current.passkeys) {
        // 保険会社にある一覧を端末に伝え、保険会社が忘れた古い passkey を、端末に片付けてもらう（D-43）
        signalAccepted(cfg.rpId, current.passkeys.userHandle, current.passkeys.passkeys.map((k) => k.id));
        setPrompt(current.passkeys.passkeys.length === 0);
      }
      setDevice(thisDevice());
    })().catch((e) => {
      setReady(true);
      setError(failText(e));
    });
    // 画面を開いたときに 1 度だけ行う
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      <h1>教材保険会社 顧客のアプリ</h1>
      <p id="error" data-testid="error" hidden={!(error ?? notice)}>{error ?? notice}</p>
      <p id="info" data-testid="info" hidden={!info}>{info}</p>
      {ready && !session && (
        <section id="login">
          <p>営業 AI エージェントに、次の範囲で申込みの取り次ぎを任せます（取決め）。</p>
          <div id="terms" data-testid="terms">
            <RowsTable rows={termsRowsOf(cfg.terms as { kinds: string[]; maxBenefit: number }[])} prefix="terms" />
          </div>
          <p className="hint">ログインと、申込みの署名には、同じパスキーを使います。パスキーがまだないときは、パスワードでログインした後に作れます。</p>
          <button id="login-button" data-testid="login" type="button" onClick={() => auth.startLogin()}>同意して保険会社にログインする</button>
        </section>
      )}
      {session && (
        <section id="signed-in">
          <p>
            ログイン中: <strong id="whoami" data-testid="whoami">{session.sub}</strong>{" "}
            <button id="signout-button" data-testid="signout" type="button" disabled={signing} onClick={() => auth.signOut().catch((e) => setError(failText(e)))}>サインアウト</button>{" "}
          </p>
        </section>
      )}
      {session && prompt && (
        <section id="passkey-prompt" data-testid="passkey-prompt">
          <p>この端末でパスキーを作りますか。パスキーは、次からのログインと、申込みの署名に使います。保険会社には、あなたのパスキーがまだありません。</p>
          <button data-testid="create-passkey" type="button" onClick={() => auth.startLogin(true)}>パスキーを作る</button>{" "}
          <button data-testid="passkey-later" type="button" onClick={() => setPrompt(false)}>後で</button>
        </section>
      )}
      {session && device && (
        <>
          <nav id="tabs">
            <button id="tab-apply" data-testid="tab-apply" type="button" className={tab === "apply" ? "tab active" : "tab"} onClick={() => setTab("apply")}>申し込む</button>
            <button id="tab-inbox" data-testid="tab-inbox" type="button" className={tab === "inbox" ? "tab active" : "tab"} onClick={() => setTab("inbox")}>受信箱と契約</button>
            <button id="tab-passkeys" data-testid="tab-passkeys" type="button" className={tab === "passkeys" ? "tab active" : "tab"} onClick={() => setTab("passkeys")}>パスキー</button>
          </nav>
          <Apply cfg={cfg} auth={auth} enabled={enabled} session={session} device={device} hidden={tab !== "apply"} onError={setError} onSigning={setSigning} />
          <Inbox session={session} device={device} hidden={tab !== "inbox"} visible={tab === "inbox"} onError={setError} />
          <Passkeys session={session} auth={auth} hidden={tab !== "passkeys"} />
        </>
      )}
    </>
  );
}
