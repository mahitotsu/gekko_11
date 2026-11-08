// 申込みの会話の状態（D-34）。カードを積み、今のカードだけを開く。画面に依らない純粋な関数で、単体テストで確かめる。
import type { Application, Intent, Offer } from "./checks.ts";

export type Step = "consult" | "offers" | "intent" | "application" | "reconcile";

export type CardData =
  | { kind: "start" }
  | { kind: "continue" }
  | { kind: "expired" }
  | { kind: "finish" }
  | { kind: "ask"; toolCallId: string; question: string; options: string[] }
  | { kind: "offers"; toolCallId: string; message?: string; reasons?: Record<string, string>; offer: Offer; verified: boolean; tampered: boolean }
  | { kind: "intent"; toolCallId: string; doc: Intent }
  | { kind: "application"; toolCallId: string; doc: Application };

export interface Card {
  id: number;
  /** ためていた営業 AI エージェントの文。カードの中に、説明の枠で出す。 */
  notes: string[];
  /** 閉じたときに読める 1 行の答え。 */
  conclusion?: string;
  data: CardData;
}

export interface ReconcileRow {
  nonce: string;
  status: string;
  text: string;
}

export interface State {
  cards: Card[];
  nextId: number;
  pendingText: string[];
  /** 営業 AI エージェントの直前の文（D23 を外したときに、確認画面に出す）。 */
  lastText: string;
  /** 直前に署名を確かめた提示（意向確認書面の案の名前を引く）。 */
  offer?: Offer;
  step: Step;
  busy: boolean;
  /** passkey の署名を頼んでから、端末が答えるまでの間。署名とページを離れる操作を止める。 */
  signing: boolean;
  error?: string;
  /** 今回署名した申込書の nonce（完了カードの照合で使う）。 */
  submitted: string;
  /** 申込書に署名した後で、営業 AI エージェントの番が終わるまでの間（提出の途中）。 */
  submitting: boolean;
  /** 新しい申し込みのボタンを出すか。 */
  started: boolean;
  confirmNew: boolean;
  /** 完了カードの照合の結果。 */
  reconcile: ReconcileRow[];
  /** 未着のまま待ちきったら、自由入力を置く。 */
  reconcileGaveUp: boolean;
}

export const initialState: State = {
  cards: [], nextId: 1, pendingText: [], lastText: "", step: "consult", busy: false, signing: false, submitted: "", submitting: false,
  started: false, confirmNew: false, reconcile: [], reconcileGaveUp: false,
};

export type Action =
  | { type: "reset" }
  | { type: "card"; data: CardData }
  | { type: "conclude"; id: number; result: string }
  | { type: "text"; content: string }
  | { type: "busy"; busy: boolean }
  | { type: "signing"; signing: boolean }
  | { type: "error"; message?: string }
  | { type: "started" }
  | { type: "submitted"; nonce: string }
  | { type: "submitting"; submitting: boolean }
  | { type: "clearSubmitted" }
  | { type: "confirmNew"; on: boolean }
  | { type: "reconcile"; rows: ReconcileRow[] }
  | { type: "reconcileGaveUp" };

/** 道具の種類から、段階を決める。質問はどの段階でも来るので、動かさない。 */
const stepOf = (data: CardData, step: Step): Step => {
  if (data.kind === "offers") return "offers";
  if (data.kind === "intent") return "intent";
  if (data.kind === "application") return "application";
  if (data.kind === "finish") return "reconcile";
  return step;
};

export function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "reset":
      // カードの番号は、始め直しても増やし続ける。同じ番号を使うと、React が前のカードの入力の状態を使い回す
      return { ...initialState, cards: [{ id: state.nextId, notes: [], data: { kind: "start" } }], nextId: state.nextId + 1 };
    case "card":
      return {
        ...state,
        cards: [...state.cards, { id: state.nextId, notes: state.pendingText, data: action.data }],
        nextId: state.nextId + 1,
        pendingText: [],
        step: stepOf(action.data, state.step),
        offer: action.data.kind === "offers" ? action.data.offer : state.offer,
      };
    case "conclude":
      return { ...state, cards: state.cards.map((c) => (c.id === action.id ? { ...c, conclusion: action.result } : c)) };
    case "text":
      return { ...state, lastText: action.content, pendingText: [...state.pendingText, action.content] };
    case "busy":
      return { ...state, busy: action.busy };
    case "signing":
      return { ...state, signing: action.signing };
    case "error":
      return { ...state, error: action.message, busy: action.message ? false : state.busy };
    case "started":
      return { ...state, started: true };
    case "submitted":
      return { ...state, submitted: action.nonce, submitting: true };
    case "submitting":
      return { ...state, submitting: action.submitting };
    case "clearSubmitted":
      return { ...state, submitted: "" };
    case "confirmNew":
      return { ...state, confirmNew: action.on };
    case "reconcile":
      return { ...state, reconcile: action.rows };
    case "reconcileGaveUp":
      return { ...state, reconcileGaveUp: true };
  }
}

/** 同じ種類の中で、最新のカードか（テストの目印は、最新のカードにだけ付ける）。 */
export const isLatestOfKind = (cards: Card[], card: Card) => cards.filter((c) => c.data.kind === card.data.kind).at(-1)?.id === card.id;
