// カードの積み重ね（D-34）。今のカードだけを開く。署名された内容と AI の言葉は、別の枠で出す（D-5、D-27）。
import { useEffect, useRef, useState, type ReactNode } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Auth } from "../auth.ts";
import { applicationRowsOf, intentRowsOf, type Application, type Intent, type Row } from "../checks.ts";
import { isLatestOfKind, type Card, type CardData, type State } from "../conversation.ts";
import type { Controller } from "../controller.ts";

/** 営業 AI エージェントの言葉の枠。HTML は文字として扱われ、スクリプトにならない。 */
export function AgentNote({ text }: { text: string }) {
  return (
    <div className="agent">
      <p className="frame-label">営業 AI エージェントの説明</p>
      <div>
        <Markdown remarkPlugins={[remarkGfm]} disallowedElements={["img"]}>{text}</Markdown>
      </div>
    </div>
  );
}

export function RowsTable({ rows, prefix }: { rows: Row[]; prefix: string }) {
  return (
    <table>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            <td>{row.label}</td>
            <td data-testid={`${prefix}-${row.key}`}>{row.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * 自由入力。許したカードにだけ置き、送ると入力欄を消す。空のときは送らない。
 * 入力した文は、会話の記録に残るので、そのことを添える（D-32）。
 */
function FreeInput(props: { prefix: string; label: string; placeholder: string; live: boolean; onSend: (text: string) => void }) {
  const [text, setText] = useState("");
  const [sent, setSent] = useState<string>();
  if (sent !== undefined) return <p className="user">{sent}</p>;
  const id = (suffix: string) => (props.live ? `${props.prefix}-${suffix}` : undefined);
  return (
    <div className="free">
      <label>{props.label}</label>
      <textarea rows={2} placeholder={props.placeholder} value={text} onChange={(e) => setText(e.target.value)} data-testid={id("input")} />
      <button
        type="button"
        data-testid={id("send")}
        onClick={() => {
          const value = text.trim();
          if (!value) return;
          setSent(value);
          props.onSend(value);
        }}
      >
        送る
      </button>
      <p className="hint">入力した文は、監査のために記録に残ります。氏名や口座番号は書かないでください。</p>
    </div>
  );
}

const TITLES: Record<CardData["kind"], string> = {
  start: "ご希望をお聞かせください",
  continue: "営業 AI エージェントから",
  expired: "ログインし直してください",
  finish: "申込みの結果",
  ask: "営業 AI エージェントからの質問",
  offers: "保険会社の案",
  intent: "意向確認書面（署名 1/2）",
  application: "申込書（署名 2/2）",
};

/** カードの枠。今のカードだけを開き、閉じたカードは、開けば読める。 */
function Frame({ card, active, attrs, children }: { card: Card; active: boolean; attrs?: Record<string, string | undefined>; children: ReactNode }) {
  const [open, setOpen] = useState(active);
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => setOpen(active), [active]);
  // 新しいブラウザの scrollIntoView は Promise を返す。返すと、React が後片付けの関数として呼んで落ちるので、返さない
  useEffect(() => {
    void ref.current?.scrollIntoView({ block: "nearest" });
  }, []);
  const result = card.conclusion;
  return (
    <details ref={ref} className="tool" open={open} onToggle={(e) => setOpen(e.currentTarget.open)} data-tool={card.data.kind} {...attrs}>
      <summary>
        {TITLES[card.data.kind]}
        {result ? `: ${result.length > 40 ? `${result.slice(0, 40)}…` : result}` : ""}
      </summary>
      {card.notes.map((text, i) => <AgentNote key={i} text={text} />)}
      {children}
    </details>
  );
}

interface CardProps {
  card: Card;
  live: boolean;
  controller: Controller;
  state: State;
  auth: Auth;
  enabled: (id: string) => boolean;
}

function Ask({ card, live, controller }: CardProps) {
  const data = card.data as Extract<CardData, { kind: "ask" }>;
  const [chosen, setChosen] = useState<number>();
  const [answered, setAnswered] = useState(false);
  const reply = (text: string) => {
    setAnswered(true);
    controller.conclude(card.id, text);
    controller.answerTool(data.toolCallId, { answer: text }).catch(controller.fail);
  };
  return (
    <>
      <p>{data.question}</p>
      {data.options.map((option, i) => (
        <button
          key={option}
          type="button"
          disabled={answered}
          className={chosen === i ? "chosen" : undefined}
          data-testid={live ? `ask-option-${i}` : undefined}
          onClick={() => {
            setChosen(i);
            reply(option);
          }}
        >
          {option}
        </button>
      ))}
      {/* 「その他」は、AI に任せず、画面が必ず足す */}
      {chosen === undefined && <FreeInput prefix="ask-other" label="その他（自由に入力）" placeholder="選択肢にないお考えを書いてください。" live={live} onSend={reply} />}
    </>
  );
}

function Offers({ card, live, controller }: CardProps) {
  const data = card.data as Extract<CardData, { kind: "offers" }>;
  const [chosen, setChosen] = useState<string>();
  const [answered, setAnswered] = useState(false);
  return (
    <>
      {data.message && <AgentNote text={data.message} />}
      {data.tampered && (
        <p className="warning" data-testid={live ? "offer-warning" : undefined}>
          営業 AI エージェントが示した案が、保険会社が署名した提示と違います。署名された案だけを表示しています。
        </p>
      )}
      <div className="issued">
        {/* G22 を外すと、営業 AI エージェントが運んだ案を、そのまま示す（悪い実装） */}
        <p className="frame-label">{data.verified ? "保険会社が署名した内容" : "営業 AI エージェントが示した案"}</p>
        <ul>
          {data.offer.offerSet.plans.map((p) => (
            <li key={p.id} className={chosen === p.id ? "chosen" : undefined} data-testid={live ? `plan-${p.id}` : undefined}>
              <strong>{p.name}</strong>
              <span>{` 毎月の保険料 ${p.monthly.toLocaleString("ja-JP")} 円 / 毎年の年金 ${p.benefit.toLocaleString("ja-JP")} 円 `}</span>
              <button
                type="button"
                disabled={answered}
                data-testid={live ? `choose-${p.id}` : undefined}
                onClick={() => {
                  setAnswered(true);
                  setChosen(p.id);
                  controller.conclude(card.id, p.name);
                  controller.answerTool(data.toolCallId, { planId: p.id, plan: p }).catch(controller.fail);
                }}
              >
                この案を選ぶ
              </button>
              {/* 推奨の理由は AI の言葉なので、保険会社の内容と見分けられる枠で出す（P-17） */}
              {data.reasons?.[p.id] && <AgentNote text={data.reasons[p.id]!} />}
            </li>
          ))}
        </ul>
      </div>
      {/* 条件を変えたいときは、営業 AI エージェントが組み立て直し、新しい提示を示す（P-17） */}
      {chosen === undefined && (
        <FreeInput
          prefix="offers-other"
          label="条件を変えて頼み直す"
          placeholder="例: 掛け金をもう少し抑えたいです。"
          live={live}
          onSend={(text) => {
            setAnswered(true);
            controller.conclude(card.id, text);
            controller.answerTool(data.toolCallId, { answer: text }).catch(controller.fail);
          }}
        />
      )}
    </>
  );
}

const GUIDE = {
  intent: ["意向確認書面", "署名 1/2", "営業 AI エージェントから届いた意向確認書面です。内容を確かめて、署名してください。"],
  application: ["申込書", "署名 2/2", "営業 AI エージェントから届いた申込書です。内容を確かめて、署名し、営業 AI エージェントに提出を任せます。"],
} as const;

/** 書類を示し、署名してもらう。画面は、署名する内容そのものから描く（G23）。署名すると、案内文を「署名済み」に置き換えて残す。 */
function Document({ card, live, controller, state, enabled }: CardProps) {
  const data = card.data as Extract<CardData, { kind: "intent" | "application" }>;
  const step = data.kind;
  const [title, count, guide] = GUIDE[step];
  const [outcome, setOutcome] = useState<"signed" | "declined">();
  // 悪い実装（G23 を外す）が出す文は、カードを出した時点の説明文に固定する
  const [summary] = useState(state.lastText);
  const id = (name: string) => (live ? name : undefined);
  const rows = step === "intent" ? intentRowsOf(data.doc as Intent, state.offer?.offerSet.plans ?? []) : applicationRowsOf(data.doc as Application);
  return (
    <>
      <p className={outcome === "signed" ? "signed" : undefined} data-testid={id(`${step}-guide`)}>
        {outcome === "signed" ? "✓ 署名済み" : outcome === "declined" ? "署名しませんでした" : guide}
      </p>
      <div className="issued" data-testid={id(`${step}-confirm`)}>
        {enabled("G23") ? (
          <>
            <p className="frame-label">署名する内容</p>
            <RowsTable rows={rows} prefix={live ? step : `old-${card.id}-${step}`} />
          </>
        ) : (
          // 悪い実装: 営業 AI エージェントの説明文を、確認画面に出す
          <p data-testid={id(`${step}-summary`)}>{summary}</p>
        )}
      </div>
      {!outcome && (
        <p aria-busy={state.signing || undefined}>
          {/* 端末の確認画面が出るまで数秒かかることがあるので、待っている間は押せなくし、待っていることを示す */}
          <button
            type="button"
            disabled={state.signing}
            data-testid={id(`sign-${step}`)}
            onClick={async () => {
              try {
                await controller.sign(data.toolCallId, step, data.doc, () => {
                  setOutcome("signed");
                  controller.conclude(card.id, "署名済み");
                });
              } catch (e) {
                controller.fail(e);
              }
            }}
          >
            {`${title}に passkey で署名する（${count}）`}
          </button>
          <button
            type="button"
            disabled={state.signing}
            data-testid={id(`cancel-${step}`)}
            onClick={() => {
              setOutcome("declined");
              controller.conclude(card.id, "署名しませんでした");
              controller.answerTool(data.toolCallId, { declined: true }).catch(controller.fail);
            }}
          >
            やめる
          </button>
        </p>
      )}
      {!outcome && state.signing && (
        <p className="waiting" role="status" data-testid={id("signing-status")}>
          端末の確認画面（PIN、指紋、顔）を待っています。表示まで数秒かかることがあります。
        </p>
      )}
    </>
  );
}

function Finish({ controller, state, live }: CardProps) {
  return (
    <>
      <p>保険会社から、営業 AI エージェントを通らずに直接届いた契約内容と、今回署名した申込書の写しを突き合わせます。</p>
      <ul id="reconcile">
        {state.reconcile.map((r) => <li key={r.nonce} data-status={r.status} data-testid={live ? `reconcile-${r.nonce}` : undefined}>{r.text}</li>)}
      </ul>
      <button type="button" data-testid={live ? "check-session" : undefined} onClick={() => controller.checkSession().catch(controller.fail)}>もう一度照合する</button>
      {state.reconcileGaveUp && (
        <FreeInput
          prefix="free"
          label="契約内容がまだ届いていません。営業 AI エージェントに伝えることがあれば書いてください"
          placeholder="例: 提出できたか教えてください。"
          live={live}
          onSend={(text) => controller.say(text).catch(controller.fail)}
        />
      )}
    </>
  );
}

export function CardView(props: CardProps & { active: boolean }) {
  const { card, active, live, controller, auth } = props;
  const data = card.data;
  const attrs = data.kind === "offers" ? { "data-nonce": data.offer.nonce, "data-testid": live ? "offers" : undefined } : undefined;
  const say = (text: string) => {
    controller.conclude(card.id, text);
    controller.say(text).catch(controller.fail);
  };
  return (
    <Frame card={card} active={active} attrs={attrs}>
      {data.kind === "start" && (
        <>
          <p>営業 AI エージェントが、質問をし、案を示し、書類を用意して、署名をお願いします。署名した書類は、営業 AI エージェントが保険会社へ取り次ぎます。</p>
          <FreeInput prefix="free" label="どのような保険をお考えですか" placeholder="例: 老後に備えて、個人年金保険を考えています。" live={live} onSend={say} />
        </>
      )}
      {data.kind === "continue" && <FreeInput prefix="free" label="お答えや、続けたいことを書いてください" placeholder="例: 案を見せてください。" live={live} onSend={say} />}
      {data.kind === "expired" && (
        <>
          <p data-testid={live ? "expired-note" : undefined}>ログインの有効期間が切れました。ログインし直すと、最初からやり直します。入力した内容と署名は消え、保険会社には届いていません。</p>
          <button type="button" data-testid={live ? "relogin" : undefined} onClick={() => auth.startLogin()}>ログインし直す</button>
        </>
      )}
      {data.kind === "ask" && <Ask {...props} />}
      {data.kind === "offers" && <Offers {...props} />}
      {(data.kind === "intent" || data.kind === "application") && <Document {...props} />}
      {data.kind === "finish" && <Finish {...props} />}
    </Frame>
  );
}

export function Cards(props: Omit<CardProps, "card" | "live">) {
  const { cards } = props.state;
  return (
    <div id="cards" data-testid="cards">
      {cards.map((card) => (
        <CardView key={card.id} {...props} card={card} live={isLatestOfKind(cards, card)} active={card.id === cards.at(-1)?.id} />
      ))}
    </div>
  );
}
