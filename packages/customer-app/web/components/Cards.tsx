// カードの積み重ね（D-34）。今のカードだけを開く。署名された内容と AI の言葉は、別の枠で出す（D-5、D-27）。
import { useEffect, useRef, useState, type ReactNode } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Auth } from "../auth.ts";
import { applicationRowsOf, intentRowsOf, type Application, type Intent, type Row } from "../checks.ts";
import { isLatestOfKind, type Card, type CardData, type ReconcileRow, type State } from "../conversation.ts";
import type { Controller } from "../controller.ts";
import { Alert, Badge, Button, ICON, Table } from "./ui.tsx";

/** 営業 AI エージェントの言葉の枠。HTML は文字として扱われ、スクリプトにならない。 */
export function AgentNote({ text }: { text: string }) {
  return (
    <div className="agent my-3 rounded-lg border border-dashed border-agent/50 bg-agent-soft px-4 py-3 text-sm">
      <p className="frame-label mb-1.5">
        <Badge tone="agent" icon="💬">営業 AI エージェントの説明</Badge>
      </p>
      <div className="agent-body">
        <Markdown remarkPlugins={[remarkGfm]} disallowedElements={["img"]}>{text}</Markdown>
      </div>
    </div>
  );
}

export function RowsTable({ rows, prefix }: { rows: Row[]; prefix: string }) {
  return (
    <Table>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            <td>{row.label}</td>
            <td data-testid={`${prefix}-${row.key}`}>{row.value}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/**
 * 自由入力。許したカードにだけ置き、送ると入力欄を消す。空のときは送らない。
 * 入力した文は、会話の記録に残るので、そのことを添える（D-32）。
 */
function FreeInput(props: { prefix: string; label: string; placeholder: string; live: boolean; onSend: (text: string) => void }) {
  const [text, setText] = useState("");
  const [sent, setSent] = useState<string>();
  if (sent !== undefined) return <p className="user ml-auto mt-3 w-fit max-w-[85%] rounded-lg bg-primary px-3.5 py-2 text-sm text-primary-foreground">{sent}</p>;
  const id = (suffix: string) => (props.live ? `${props.prefix}-${suffix}` : undefined);
  return (
    <div className="free mt-4 space-y-2">
      <label className="block text-sm font-medium">{props.label}</label>
      <textarea
        rows={2}
        placeholder={props.placeholder}
        value={text}
        onChange={(e) => setText(e.target.value)}
        data-testid={id("input")}
        className="block w-full rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-2 focus-visible:outline-primary"
      />
      <Button
        variant="primary"
        data-testid={id("send")}
        onClick={() => {
          const value = text.trim();
          if (!value) return;
          setSent(value);
          props.onSend(value);
        }}
      >
        送る
      </Button>
      <p className="hint text-xs text-muted-foreground">入力した文は、監査のために記録に残ります。氏名や口座番号は書かないでください。</p>
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
    <details
      ref={ref}
      className="tool rounded-xl border bg-card px-5 py-4 shadow-sm open:border-l-4 open:border-l-primary"
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
      data-tool={card.data.kind}
      {...attrs}
    >
      <summary className="mb-0 [details[open]>&]:mb-3">
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
      <p className="mb-3">{data.question}</p>
      <div className="flex flex-wrap gap-2">
      {data.options.map((option, i) => (
        <Button
          key={option}
          disabled={answered}
          className={chosen === i ? "chosen ring-2 ring-verified" : undefined}
          data-testid={live ? `ask-option-${i}` : undefined}
          onClick={() => {
            setChosen(i);
            reply(option);
          }}
        >
          {option}
        </Button>
      ))}
      </div>
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
        <Alert tone="danger" className="warning my-3" data-testid={live ? "offer-warning" : undefined}>
          営業 AI エージェントが示した案が、保険会社が署名した提示と違います。署名された案だけを表示しています。
        </Alert>
      )}
      <div className={`issued rounded-lg border p-4 ${data.verified ? "border-verified/50 bg-verified-soft" : "border-agent/50 bg-agent-soft"}`}>
        {/* G22 を外すと、営業 AI エージェントが運んだ案を、そのまま示す（悪い実装） */}
        <p className="frame-label mb-3">
          {data.verified ? <Badge tone="verified" icon="🔒">保険会社が署名した内容</Badge> : <Badge tone="agent" icon="💬">営業 AI エージェントが示した案</Badge>}
        </p>
        <ul className="space-y-2">
          {data.offer.offerSet.plans.map((p) => (
            <li
              key={p.id}
              className={`flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border bg-card px-4 py-3 ${chosen === p.id ? "chosen ring-2 ring-verified" : ""}`}
              data-testid={live ? `plan-${p.id}` : undefined}
            >
              <strong className="basis-full sm:basis-auto">{p.name}</strong>
              <span className="grow text-sm text-muted-foreground">{` 毎月の保険料 ${p.monthly.toLocaleString("ja-JP")} 円 / 毎年の年金 ${p.benefit.toLocaleString("ja-JP")} 円 `}</span>
              <Button
                variant="primary"
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
              </Button>
              {/* 推奨の理由は AI の言葉なので、保険会社の内容と見分けられる枠で出す（P-17） */}
              {data.reasons?.[p.id] && (
                <div className="basis-full">
                  <AgentNote text={data.reasons[p.id]!} />
                </div>
              )}
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
      <p className={outcome === "signed" ? "signed mb-3 font-semibold text-verified" : "mb-3"} data-testid={id(`${step}-guide`)}>
        {outcome === "signed" ? "✓ 署名済み" : outcome === "declined" ? "署名しませんでした" : guide}
      </p>
      <div className={`issued rounded-lg border p-4 ${enabled("G23") ? "border-verified/50 bg-verified-soft" : "border-agent/50 bg-agent-soft"}`} data-testid={id(`${step}-confirm`)}>
        {enabled("G23") ? (
          <>
            <p className="frame-label mb-2">
              <Badge tone="verified" icon="✍">署名する内容</Badge>
            </p>
            <div className="rounded-md border bg-card">
              <RowsTable rows={rows} prefix={live ? step : `old-${card.id}-${step}`} />
            </div>
          </>
        ) : (
          // 悪い実装: 営業 AI エージェントの説明文を、確認画面に出す
          <p data-testid={id(`${step}-summary`)}>{summary}</p>
        )}
      </div>
      {!outcome && (
        <p aria-busy={state.signing || undefined} className="mt-4 flex flex-wrap gap-2">
          {/* 端末の確認画面が出るまで数秒かかることがあるので、待っている間は押せなくし、待っていることを示す */}
          <Button
            variant="primary"
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
          </Button>
          <Button
            disabled={state.signing}
            data-testid={id(`cancel-${step}`)}
            onClick={() => {
              setOutcome("declined");
              controller.conclude(card.id, "署名しませんでした");
              controller.answerTool(data.toolCallId, { declined: true }).catch(controller.fail);
            }}
          >
            やめる
          </Button>
        </p>
      )}
      {!outcome && state.signing && (
        <p className="waiting mt-3 text-sm text-muted-foreground" role="status" data-testid={id("signing-status")}>
          端末の確認画面（PIN、指紋、顔）を待っています。表示まで数秒かかることがあります。
        </p>
      )}
    </>
  );
}

function Finish({ controller, state, live }: CardProps) {
  return (
    <>
      <p className="mb-3">保険会社から、営業 AI エージェントを通らずに直接届いた契約内容と、今回署名した申込書の写しを突き合わせます。</p>
      <ReconcileList id="reconcile" rows={state.reconcile} testid={(r) => (live ? `reconcile-${r.nonce}` : undefined)} />
      <Button className="mt-3" data-testid={live ? "check-session" : undefined} onClick={() => controller.checkSession().catch(controller.fail)}>もう一度照合する</Button>
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
          <p className="text-sm text-muted-foreground">営業 AI エージェントが、質問をし、案を示し、書類を用意して、署名をお願いします。署名した書類は、営業 AI エージェントが保険会社へ取り次ぎます。</p>
          <FreeInput prefix="free" label="どのような保険をお考えですか" placeholder="例: 老後に備えて、個人年金保険を考えています。" live={live} onSend={say} />
        </>
      )}
      {data.kind === "continue" && <FreeInput prefix="free" label="お答えや、続けたいことを書いてください" placeholder="例: 案を見せてください。" live={live} onSend={say} />}
      {data.kind === "expired" && (
        <>
          <p data-testid={live ? "expired-note" : undefined}>ログインの有効期間が切れました。ログインし直すと、最初からやり直します。入力した内容と署名は消え、保険会社には届いていません。</p>
          <Button className="mt-3" variant="primary" data-testid={live ? "relogin" : undefined} onClick={() => auth.startLogin()}>ログインし直す</Button>
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
    <div id="cards" data-testid="cards" className="space-y-3">
      {cards.map((card) => (
        <CardView key={card.id} {...props} card={card} live={isLatestOfKind(cards, card)} active={card.id === cards.at(-1)?.id} />
      ))}
    </div>
  );
}

/** 照合の結果の一覧。一致は ✓、届くのを待つものは …、食い違いと覚えのない契約は ⚠ と色で示す。 */
const RECONCILE: Record<string, [string, string]> = {
  match: ["✓", "text-verified"],
  missing: ["…", "bg-warning-soft"],
};
export function ReconcileList({ id, rows, testid }: { id?: string; rows: ReconcileRow[]; testid: (r: ReconcileRow) => string | undefined }) {
  if (rows.length === 0) return <ul id={id} />;
  return (
    <ul id={id} className="divide-y rounded-lg border">
      {rows.map((r) => (
        <li key={r.nonce} data-status={r.status} data-testid={testid(r)} data-icon={(RECONCILE[r.status] ?? ["⚠"])[0]} className={`flex gap-2 px-4 py-2.5 text-sm before:font-bold ${ICON} ${(RECONCILE[r.status] ?? ["", "bg-danger-soft text-danger"])[1]}`}>
          {r.text}
        </li>
      ))}
    </ul>
  );
}
