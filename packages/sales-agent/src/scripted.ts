// Claude を使わないときの台本（vulnerable の名前空間と、認証情報のない環境。D-23）。
// Claude と同じ道具を、決まった順で呼ぶ: 質問 → 案 → 意向確認書面 → 申込書 → 提出。
import { callMcp } from "./mcp.ts";
import { submitSigned } from "./submit.ts";
import type { Offer } from "./draft.ts";
import type { Thread } from "./thread.ts";

export interface Plan {
  id: string;
  name: string;
  kind: string;
  benefit: number;
  monthly: number;
}

/** 顧客の文 1 つに応じる（営業 AI エージェントの 1 回の番）。 */
export async function scriptedTurn(t: Thread, message: string, call: typeof callMcp = callMcp): Promise<void> {
  if (/契約|一覧|照会/.test(message)) {
    const r = await call(t.ctx, "list_contracts");
    t.say(r.isError ? `契約を調べられませんでした: ${JSON.stringify(r.body)}` : `契約は ${r.body.contracts.length} 件です。`);
    return;
  }
  const kind = await t.frontend("ask_customer", {
    question: "年金の受け取り方は、どちらをお考えですか。",
    options: ["決まった期間に受け取る（確定年金）", "生きている間ずっと受け取る（終身年金）"],
  });
  const r = await call(t.ctx, "get_offers");
  if (r.isError || r.body.error) {
    t.say(`案を取得できませんでした: ${JSON.stringify(r.body)}`);
    return;
  }
  t.offer = r.body as Offer;
  const chosen = await t.frontend("present_offers", { message: "保険会社が用意した案です。比べて、1 つ選んでください。" });
  const planId = /選んだ案: (\S+)/.exec(chosen)?.[1];
  if (!planId) {
    t.say("案が選ばれなかったので、ここで止めます。");
    return;
  }
  const plan = t.offer.offerSet.plans.find((p) => p.id === planId);
  const name = `「${plan?.name ?? planId}」（月額の保険料 ${plan?.monthly.toLocaleString("ja-JP") ?? "?"} 円）`;
  t.say(`${name}で、意向確認書面を用意しました。内容を確かめて、署名してください。`);
  const intent = await t.frontend("present_intent", { planId, wish: `老後の生活費に備えたい（受け取り方: ${kind}）` });
  if (!intent.includes("署名しました")) {
    t.say("意向確認書面への署名がなかったので、申込みは進めません。");
    return;
  }
  t.say(`${name}で、申込書を用意しました。署名いただければ、保険会社へ取り次ぎます。`);
  const application = await t.frontend("present_application", { planId });
  if (!application.includes("署名しました")) {
    t.say("申込書への署名がなかったので、提出しません。");
    return;
  }
  const s = await submitSigned(t, call);
  t.say(s.isError || s.body?.error ? `提出を断られました: ${JSON.stringify(s.body)}` : `署名済みの申込書を、保険会社へ取り次ぎました（${s.body?.contract?.contractId ?? ""}）。契約内容は、保険会社から直接届きます。`);
}
