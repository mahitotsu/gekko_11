// シナリオ 4（R2 × A4）: 期限切れのトークンで、本人の知らない申込みを、保険会社のシステムへ直接出す。
// トークンの期限（5 分）は実際に過ぎるまで待つ。最初に回数分のトークンを受け取り、期限が切れるのを 1 回だけ待つ。
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
  { name: "vulnerable（D6、D10、D13、D14 が全てある）: 被害は出ない", ns: "vulnerable", gaps: {}, harmed: false },
  { name: "vulnerable（D6 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { D6: "off" }, harmed: false },
  { name: "vulnerable（D10 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { D10: "off" }, harmed: false },
  { name: "vulnerable（D13 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { D13: "off" }, harmed: false },
  { name: "vulnerable（D14 だけを外す）: ほかの防御が止める", ns: "vulnerable", gaps: { D14: "off" }, harmed: false },
  // 期限が切れるまで待つ間に、トークンを結んだ SVID が入れ替わることがある（F-G54）。入れ替わると D26 でも止まるので、
  // 被害を確実に再現するため、最小の組に D26 も含める。D26 が止めるかは時刻に依るので、「どれか 1 つで止める防御」には入れない
  {
    name: "vulnerable（D6、D10、D13、D14、D26 を外す）: 被害が出る",
    ns: "vulnerable",
    gaps: { D6: "off", D10: "off", D13: "off", D14: "off", "D26@insurer-backend": "off" },
    harmed: true,
  },
];

const prepared: Prepared[] = [];

/** 事務サービスの役（probe-mcp-1）が、正規の経路で C を受け取り、期限が切れるまで持っておく。 */
async function prepare(ns: Ns): Promise<Prepared> {
  const alice = await new Customer(ns, "alice").setup();
  const offer = await offerFor(alice);
  const c = await exchangeAs(ns, "probe-mcp-1", await atMcp(alice), "insurer-backend");
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
      await backendPost(p.ns, p.token, p.sub);
      if (run.ns === "vulnerable") await setDefenses({});
      expect((await contractsOf(p.ns, p.nonce)).length > 0).toBe(run.harmed);
    });
  });
});
