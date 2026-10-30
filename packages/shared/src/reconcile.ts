import type { Application, Notice } from "./models.js";

export interface Reconciled {
  nonce: string;
  status: "match" | "mismatch" | "missing" | "unexpected";
  diffs: string[];
}

// 自動照合。顧客の手元に残る申込みの写しと、保険会社から直接届いた通知を突き合わせる。
// 通知が来ない(missing)、内容が違う(mismatch)、覚えのない通知(unexpected)を見つける。AI を通らない照合である。
export function reconcile(mine: Application[], notices: Notice[]): Reconciled[] {
  const out: Reconciled[] = [];
  for (const app of mine) {
    const hits = notices.filter((n) => n.contract.nonce === app.nonce);
    if (hits.length === 0) { out.push({ nonce: app.nonce, status: "missing", diffs: ["通知が届いていません"] }); continue; }
    for (const n of hits) {
      const c = n.contract;
      const diffs: string[] = [];
      if (c.customer !== app.customer) diffs.push("契約者");
      if (c.plan.id !== app.plan.id) diffs.push("案");
      if (c.plan.benefit !== app.plan.benefit) diffs.push("年金の年額");
      if (c.plan.monthly !== app.plan.monthly) diffs.push("保険料");
      if (c.offerSetId !== app.offerSetId) diffs.push("提示集合");
      out.push({ nonce: app.nonce, status: diffs.length ? "mismatch" : "match", diffs });
    }
  }
  const known = new Set(mine.map((a) => a.nonce));
  for (const n of notices) if (!known.has(n.contract.nonce)) out.push({ nonce: n.contract.nonce, status: "unexpected", diffs: ["申し込んだ覚えのない契約です"] });
  return out;
}
