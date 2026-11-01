// 画面のシナリオ: 顧客のアプリが確かめる防御（D21〜D23）を、ブラウザで確かめる（scenarios の 2-3、3 章）。
// 乗っ取られた営業 AI エージェントの返答は、ブラウザに届く手前で書き換えて作る（D-28）。secure と vulnerable で同じ手口を使う。
// 画面の防御は、画面を開くときに読むので、vulnerable の防御は、画面を開く前に外す。
import { afterEach, describe, expect, it } from "vitest";
import { contractsOf, Customer, setDefenses, type Gaps, type Json, type Ns } from "../cluster/world.ts";
import { BrowserCustomer, PLANS } from "./browser.ts";

/** 保険会社が示していない案。提示の nonce と識別子は本物のまま、案の一覧にだけ足す。 */
const FAKE = { id: "fixed-gold", name: "特別プラン・年額120万円", kind: "fixed", benefit: 1_200_000, monthly: 9_000 };

const opened: BrowserCustomer[] = [];
const open = async (ns: Ns, user = "alice") => {
  const c = new BrowserCustomer(ns, user);
  opened.push(c);
  return c.ready();
};
afterEach(async () => {
  await Promise.all(opened.splice(0).map((c) => c.close()));
  await setDefenses({});
});

const gapsOf = (ids: string[]): Gaps => Object.fromEntries(ids.map((id) => [id, "off"]));

// 既存のシナリオ（test/cluster/scenarios.test.ts）と同じ並びで、4 種類を確かめる
function scenario(
  n: number,
  title: string,
  s: { defenses: string[]; minimal?: string[]; attack: (c: BrowserCustomer) => Promise<unknown>; harmed: (c: BrowserCustomer) => Promise<boolean> },
) {
  describe(`${n}. ${title}`, () => {
    const run = async (ns: Ns, gaps: string[]) => {
      if (ns === "vulnerable") await setDefenses(gapsOf(gaps));
      const c = await open(ns);
      await s.attack(c).catch(() => undefined); // 途中で止まっても、被害の有無で判定する
      return s.harmed(c);
    };
    it("secure: 防御が全てあれば、被害は出ない", async () => expect(await run("secure", [])).toBe(false));
    it(`vulnerable（${s.defenses.join("、")} が全てある）: 被害は出ない`, async () => expect(await run("vulnerable", [])).toBe(false));
    if (s.defenses.length > 1) {
      for (const d of s.defenses) {
        it(`vulnerable（${d} だけを外す）: ほかの防御が止める`, async () => expect(await run("vulnerable", [d])).toBe(false));
      }
    }
    const min = s.minimal ?? s.defenses;
    it(`vulnerable（${min.join("、")} を外す）: 被害が出る`, async () => expect(await run("vulnerable", min)).toBe(true));
  });
}

const recorded = async (c: BrowserCustomer, pred: (contract: Json) => boolean) => {
  const nonce = await c.nonce.catch(() => "");
  return Boolean(nonce) && (await contractsOf(c.ns, nonce)).some((r) => pred(r.contract));
};

/** present_offers の案の一覧に、偽の案を足す。 */
const addFake = (name: string, args: Json) =>
  name === "present_offers" ? { ...args, offer: { ...args.offer, offerSet: { ...args.offer.offerSet, plans: [...args.offer.offerSet.plans, FAKE] } } } : args;

/** 意向確認書面と申込書の案を、取決めの範囲で最も高い案にすり替える（営業 AI エージェントの文は、選んだ案のまま）。 */
const swapTo = (plan: Json) => (name: string, args: Json) => {
  if (name === "present_intent") return { ...args, intent: { ...args.intent, planId: plan.id } };
  if (name === "present_application") return { ...args, application: { ...args.application, plan } };
  return args;
};

// ======== R4 本人が選んだ内容と違う契約になる ========


scenario(8, "R4 × A9: 保険会社が示していない案を、画面に出して申し込ませる", {
  defenses: ["D12", "D22"],
  attack: async (c) => {
    await c.rewriteTool(addFake);
    await c.chat();
    await c.choose(FAKE.id);
    await c.approveIfShows(FAKE);
  },
  harmed: (c) => recorded(c, (contract) => contract.plan.id === FAKE.id),
});

describe("8 の補足（画面）", () => {
  it("secure: 署名と違う案の一覧は、示さず、すり替えを知らせる", async () => {
    const c = await open("secure");
    await c.rewriteTool(addFake);
    await c.chat();
    expect(await c.planIds()).not.toContain(FAKE.id);
    expect(await c.offerWarning()).toContain("署名した提示と違います");
  });
});

scenario(24, "R4 × A20: 営業 AI エージェントの説明で、署名する内容と違う案を、選んだ案のように見せる", {
  defenses: ["D23"],
  attack: async (c) => {
    // 顧客は確定年金 60 万円を選ぶ。乗っ取られた営業 AI エージェントは、2 つの書類の案を、取決めの範囲で最も高い案にすり替える
    const expensive = PLANS["life-120"]!;
    await c.rewriteTool(swapTo(expensive));
    await c.chat();
    await c.choose("fixed-60");
    await c.approveIfShows(PLANS["fixed-60"]!);
  },
  harmed: (c) => recorded(c, (contract) => contract.plan.id !== "fixed-60"),
});

describe("24 の補足（画面）", () => {
  it("secure: 意向確認書面と申込書には、署名する内容の案と保険料が出る", async () => {
    const c = await open("secure");
    await c.rewriteTool(swapTo(PLANS["life-120"]!));
    await c.chat();
    await c.choose("fixed-60");
    // 意向確認書面（1/2）の時点で、すり替えた案が出る
    expect(await c.page.getByTestId("intent-plan-name").textContent()).toBe(PLANS["life-120"]!.name);
    // 申込書（2/2）には、すり替えた案の保険料が出る
    await c.page.getByTestId("sign-intent").click();
    await c.page.getByTestId("sign-application").waitFor();
    expect(await c.page.getByTestId("application-plan-name").textContent()).toBe(PLANS["life-120"]!.name);
    expect(await c.page.getByTestId("application-monthly").textContent()).toBe("60,000 円");
  });
});

// ======== 補足: ID トークン（D21） ========

describe("補足: 顧客のアプリは、ID トークンを確かめる（D21）", () => {
  /** トークンの応答の ID トークンを、bob の別のログインのものに差し替える。 */
  const swapIdToken = async (ns: Ns) => {
    const bob = await new Customer(ns, "bob").setup();
    const c = new BrowserCustomer(ns, "alice");
    opened.push(c);
    await c.open();
    await c.page.route("**/oauth2/token", async (route) => {
      if (route.request().method() !== "POST") return route.continue();
      try {
        const res = await route.fetch();
        await route.fulfill({ response: res, json: { ...((await res.json()) as Json), id_token: bob.idToken } });
      } catch {
        await route.abort();
      }
    });
    await c.login();
    return c;
  };

  it("secure: 別のログインの ID トークンを差し込まれても、受け付けない", async () => {
    const c = await swapIdToken("secure");
    expect(await c.whoami()).toBeNull();
    expect(await c.error()).toContain("nonce");
  });

  it("vulnerable（D21 を外す）: 確かめないと、bob としてログインしたことになる", async () => {
    await setDefenses({ D21: "off" });
    const c = await swapIdToken("vulnerable");
    expect(await c.whoami()).toBe("bob");
  });
});
