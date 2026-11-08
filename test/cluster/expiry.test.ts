// シナリオ 4（R2 × A4）: 期限切れのトークンで、本人の知らない申込みを、保険会社のシステムへ直接出す。
// トークン C の期限（1 分）は実際に過ぎるまで待つ。最初に回数分のトークンを受け取り、期限が切れるのを 1 回だけ待つ。
import { beforeAll, describe, expect, it } from "vitest";
import { atMcp, backendPost, contractsOf, Customer, exchangeAs, offerFor, setDefenses, type Gaps, type Ns, type Submission } from "./world.ts";

interface Prepared {
  ns: Ns;
  token: string;
  nonce: string;
  sub: Submission;
}

const RUNS: { name: string; ns: Ns; gaps: Gaps; harmed: boolean }[] = [
  { name: "secure: 防御が全てあれば、被害は出ない", ns: "secure", gaps: {}, harmed: false },
  { name: "vulnerable（G6、G10、G13、G14 が全てある）: 被害は出ない", ns: "vulnerable", gaps: {}, harmed: false },
  { name: "vulnerable（G6 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { G6: "off" }, harmed: false },
  { name: "vulnerable（G10 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { G10: "off" }, harmed: false },
  { name: "vulnerable（G13 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { G13: "off" }, harmed: false },
  { name: "vulnerable（G14 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { G14: "off" }, harmed: false },
  // 期限が切れるまで待つ間に、トークンを結んだ SVID が入れ替わることがある（F-G54）。入れ替わると G26 でも止まるので、
  // 被害を確実に再現するため、最小の組に G26 も含める。G26 が止めるかは時刻に依るので、「どれか 1 つで止める防御」には入れない
  {
    name: "vulnerable（G6、G10、G13、G14、G26 を外す）: 被害が出る",
    ns: "vulnerable",
    gaps: { G6: "off", G10: "off", G13: "off", G14: "off", "G26@insurer-backend": "off" },
    harmed: true,
  },
];

const prepared: Prepared[] = [];

/** 事務サービスの役（probe-mcp-1）が、正規の経路で C を受け取り、期限が切れるまで持っておく。 */
async function prepare(ns: Ns): Promise<Prepared> {
  const alice = await new Customer(ns, "alice").setup();
  const offer = await offerFor(alice);
  const c = await exchangeAs(ns, "probe-mcp-1", await atMcp(alice), "insurer-backend");
  if (!c.body?.access_token) throw new Error(`C を受け取れない: ${JSON.stringify(c)}`);
  const sub = { ...alice.prepare(offer, "fixed-60"), assertion: null, intentAssertion: null };
  return { ns, token: c.body.access_token, nonce: offer.nonce, sub };
}

beforeAll(async () => {
  await setDefenses({});
  for (const run of RUNS) prepared.push(await prepare(run.ns));
  const exp = Math.max(...prepared.map((p) => JSON.parse(Buffer.from(p.token.split(".")[1]!, "base64url").toString()).exp));
  const wait = exp * 1000 - Date.now() + 5_000;
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
}, 900_000);

describe("4. R2 × A4: 期限切れのトークンで、本人の知らない申込みを出す", () => {
  RUNS.forEach((run, i) => {
    it(run.name, async () => {
      if (run.ns === "vulnerable") await setDefenses(run.gaps);
      const p = prepared[i]!;
      const r = await backendPost(p.ns, p.token, p.sub);
      if (run.ns === "vulnerable") await setDefenses({});
      expect((await contractsOf(p.ns, p.nonce)).length > 0, JSON.stringify(r)).toBe(run.harmed);
    });
  });
});
