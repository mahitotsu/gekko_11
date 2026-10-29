// シナリオ: リスク × 手口 × 防御の漏れ。全シナリオの攻撃は申込みである。
// 台本役の「営業 AI エージェント」は、プロンプトインジェクションで乗っ取られた AI を模す(渡された値を好きに書き換える)。
// 各シナリオで、(1) 防御がすべてあれば被害が出ない、(2) 止める防御を 1 つずつ外しても、ほかの防御が止める、
// (3) 最小の漏れの組を外すと被害が出る、を確かめる。
import { CompactSign, SignJWT, generateKeyPair, importJWK } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  agentKey, canonical, challengeOf, offerSetId, reconcile, signOfferSet, urls, verifyOfferSetRemote,
  type Contract, type InsuranceTerms, type Notice, type OfferSet, type Plan,
} from "@gekko/shared";
import { deriveContract } from "../packages/insurer-backend/src/app.js";
import {
  Customer, TERMS, connectMcp, exchange, payloadOf, resetWorld, revokeClient, salesConfig, setBackend, setMcp, startWorld,
  type OfferResult, type Submission,
} from "./helpers/world.js";

let world: Awaited<ReturnType<typeof startWorld>>;
let alice: Customer, bob: Customer, mallory: Customer;
beforeAll(async () => { world = await startWorld(); });
afterAll(() => world.stop());
beforeEach(async () => {
  await resetWorld();
  [alice, bob, mallory] = await Promise.all(["alice", "bob", "mallory"].map(async (u) => {
    const c = await new Customer(u).login();
    return c.registerSeal();
  }));
});
afterEach(() => vi.useRealTimers());

const MEDICAL_ONLY: InsuranceTerms[] = [{ type: "insurance_application", kinds: ["medical"], maxBenefit: 10_000_000 }];
const WIDE = JSON.stringify([{ type: "insurance_application", kinds: ["medical", "death"], maxBenefit: 100_000_000 }]);
const FULL_ROUTE = "insurer-mcp,sales-agent"; // 正規の経路で取り次がれたときの経由の記録

// ---- 補助 ----
// 顧客が営業 AI エージェントの窓口に来て、替えたトークンで事務サービスにつながるまで
async function atMcp(who: Customer = alice, terms: InsuranceTerms[] = TERMS) {
  const ticket = await who.salesTicket(terms);
  const routed = (await exchange("sales-agent", ticket, "insurer-mcp")).access_token!;
  return { ticket, routed, mcp: await connectMcp(routed) };
}
type Mcp = Awaited<ReturnType<typeof atMcp>>["mcp"];
const getOffer = async (mcp: Mcp) => (await mcp.call<OfferResult>("get_offers")).body;
const apply = (mcp: Mcp, sub: object, extras?: Record<string, unknown>) =>
  mcp.call("submit_application", { ...sub, ...(extras ? { extras } : {}) });
// 保険会社のシステムへ、直接申し込む(事務サービスを通らない)
const backendPost = (token: string, body: object) => fetch(`${urls.insurerBackend}/applications`, {
  method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
});
const backendState = async () =>
  (await (await fetch(`${urls.insurerBackend}/debug/state`)).json()) as {
    contracts: { contract: Contract; by: string[] }[]; outbox: { to: string; notice: Notice; delivered: boolean }[];
  };
const recorded = async (pred: (r: { contract: Contract; by: string[] }) => boolean) => (await backendState()).contracts.some(pred);
const noticesOf = async (user: string) => (await (await fetch(`${urls.customerApp}/api/notices?customer=${user}`)).json()) as Notice[];
const planOf = (offer: OfferResult, id: string) => offer.offerSet.plans.find((p) => p.id === id)!;
const claimsOf = async (who: Customer) => payloadOf(await who.salesTicket()).verified_claims;
// 攻撃の材料として、正規の経路で、顧客宛ての提示を受け取る(防御の設定に左右されない)
async function offerFor(who: Customer): Promise<OfferResult> {
  const routed = (await exchange("sales-agent", await who.salesTicket(), "insurer-mcp")).access_token!;
  const bt = (await exchange("insurer-mcp", routed, "insurer-backend")).access_token!;
  const r = await fetch(`${urls.insurerBackend}/offers`, { method: "POST", headers: { authorization: `Bearer ${bt}`, "content-type": "application/json" }, body: "{}" });
  return (await r.json()) as OfferResult;
}
// 顧客の署名のない申込み(乗っ取られた AI は、顧客の署名を作れない)
const unsigned = (s: Submission) => ({ ...s, assertion: null, intentAssertion: null });
// 偽造したトークン(保険会社の鍵ではない鍵で署名する)
async function forgedFor(user: string, verified_claims: unknown) {
  const { privateKey } = await generateKeyPair("ES256");
  return new SignJWT({ scope: "consult apply", authorization_details: TERMS, verified_claims })
    .setProtectedHeader({ alg: "ES256", typ: "at+jwt" }).setIssuer("insurer-auth").setSubject(user)
    .setAudience("insurer-backend").setIssuedAt().setExpirationTime("10m").sign(privateKey);
}
function algNoneFor(user: string, verified_claims: unknown) {
  const b = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b({ alg: "none", typ: "at+jwt" })}.${b({ iss: "insurer-auth", sub: user, aud: "insurer-backend", iat: 1, exp: 4102444800, scope: "consult apply", authorization_details: TERMS, verified_claims })}.`;
}

// ---- 防御(外す設定) ----
type Gap = () => void;
const D = {
  "D1 MCP の宛先確認": () => setMcp({ incoming: "no-aud" }),
  "D2 MCP のトークンの交換(素通し)": () => setMcp({ backendAuth: "passthrough" }),
  "D2 MCP のトークンの交換(自分の資格)": () => setMcp({ backendAuth: "client-credentials" }),
  "D3 絞った発行": () => { process.env.INSURER_MODE_AUTH = "bad"; },
  "D5 トークンの署名": () => setBackend({ ticket: "no-signature" }),
  "D6 トークンの期限": () => setBackend({ ticket: "no-exp" }),
  "D7 トークンの宛先": () => setBackend({ ticket: "no-aud" }),
  "D8 トークンの種類": () => setBackend({ ticket: "no-typ" }),
  "D9 顧客をトークンの本人から決める": () => setBackend({ trustFromUser: true }),
  "D10 発行元への問い合わせ": () => setBackend({ registration: "none" }),
  "D11 本人確認の属性をトークンから読む": () => setBackend({ identity: "agent-claim" }),
  "D12 提示の署名": () => setBackend({ offers: "none" }),
  "D13 顧客の署名と内容の照合": () => setBackend({ seal: "none" }),
  "D14 被保険者の署名": () => setBackend({ insured: "none" }),
  "D15 署名の連鎖": () => setBackend({ chain: "none" }),
  "D16 取決め": () => setBackend({ range: "none" }),
  "D17 使い捨ての値": () => setBackend({ nonce: "none" }),
  "D18 記録の導出": () => setBackend({ ingest: "manual" }),
  "D19 登録済みの通知先": () => setBackend({ notify: "from-application" }),
} satisfies Record<string, Gap>;
type DefName = keyof typeof D;

// ---- シナリオの型 ----
// defenses: どれか 1 つでもあれば被害が出ない防御。minimal: 被害が出るのに外す必要がある防御(省略時は defenses 全部)。
function scenario<C>(n: number, title: string, s: {
  defenses: DefName[]; minimal?: DefName[];
  prepare: () => Promise<C>; attack: (c: C) => Promise<unknown>; harmed: (c: C) => Promise<boolean>;
}, extra?: () => void) {
  describe(`${n}. ${title}`, () => {
    const run = async (gaps: DefName[]) => {
      gaps.forEach((g) => D[g]());
      const c = await s.prepare();
      await s.attack(c).catch(() => undefined); // 途中で拒否されても、被害の有無で判定する
      return s.harmed(c);
    };
    it(`good(${s.defenses.join("、")}): 被害は出ない`, async () => expect(await run([])).toBe(false));
    if (s.defenses.length > 1) {
      for (const d of s.defenses) it(`good(${d} だけを外す): ほかの防御が止める`, async () => expect(await run([d])).toBe(false));
    }
    const min = s.minimal ?? s.defenses;
    it(`bad(${min.join("、")} を外す): 被害が出る`, async () => expect(await run(min)).toBe(true));
    extra?.();
  });
}

describe("基本の流れ(good)", () => {
  it("営業 AI エージェントが案を示し、顧客が選んで署名し、保険会社のシステムが記録し、顧客へ直接通知する", async () => {
    const ticket = await alice.salesTicket();
    const auth = { authorization: `Bearer ${ticket}`, "content-type": "application/json" };
    const chat = (await (await fetch(`${urls.salesAgent}/chat`, { method: "POST", headers: auth, body: JSON.stringify({ message: "医療の保険を見たい" }) })).json()) as { offer: OfferResult; engine: string };
    expect(chat.engine).toBe("scripted");
    expect(chat.offer.offerSet.plans.length).toBeGreaterThan(1); // 複数の案

    // 顧客のアプリが、保険会社の署名を確かめてから案を表示する
    const offer = await verifyOfferSetRemote(chat.offer.offerJws);
    expect(offer.customer).toBe("alice");

    const sub = alice.prepare(chat.offer, "med-plus");
    const done = await fetch(`${urls.salesAgent}/submit`, { method: "POST", headers: auth, body: JSON.stringify({ ...sub, offerSet: chat.offer.offerSet }) });
    expect(done.status).toBe(200);

    // 監査用: 署名済みの申込みと、経由した窓口が残る
    const st = await backendState();
    expect(st.contracts).toHaveLength(1);
    expect(st.contracts[0]!.contract.plan.id).toBe("med-plus");
    expect(st.contracts[0]!.by.join()).toBe(FULL_ROUTE);

    // 営業 AI エージェントを通らない通知と、顧客の手元の写しが一致する
    const r = reconcile([sub.application], await noticesOf("alice"));
    expect(r).toEqual([{ nonce: sub.application.nonce, status: "match", diffs: [] }]);
  });
});

// ======== R1 他人名義の申込みが通る ========
scenario(1, "R1 × A1: 営業 AI が欄に「bob」と書き、bob 名義で申し込む", {
  defenses: ["D2 MCP のトークンの交換(自分の資格)", "D9 顧客をトークンの本人から決める", "D11 本人確認の属性をトークンから読む", "D13 顧客の署名と内容の照合", "D15 署名の連鎖"],
  prepare: async () => ({ sub: unsigned(bob.prepare(await offerFor(bob), "med-light")), claims: await claimsOf(alice) }),
  attack: async ({ sub, claims }) => apply((await atMcp(alice)).mcp, sub, { verified_claims: claims }),
  harmed: async () => recorded((r) => r.contract.customer === "bob"),
}, () => {
  it("替えたトークンでは、sub は alice のまま、act に経由した窓口が残る", async () => {
    const p = payloadOf((await atMcp()).routed);
    expect(p.sub).toBe("alice");
    expect(p.act).toEqual({ sub: "sales-agent" });
  });
});

scenario(2, "R1 × A3: 偽造したトークン(本人を bob)で、bob 名義で申し込む", {
  defenses: ["D5 トークンの署名", "D10 発行元への問い合わせ", "D13 顧客の署名と内容の照合", "D15 署名の連鎖"],
  prepare: async () => ({ sub: unsigned(bob.prepare(await offerFor(bob), "med-light")), token: await forgedFor("bob", await claimsOf(bob)) }),
  attack: async ({ sub, token }) => backendPost(token, sub),
  harmed: async () => recorded((r) => r.contract.customer === "bob"),
}, () => {
  const algNone = async () => ({ sub: unsigned(bob.prepare(await offerFor(bob), "med-light")), token: algNoneFor("bob", await claimsOf(bob)) });
  it("good: alg=none のトークンも、署名の確認で弾かれる", async () => {
    const { sub, token } = await algNone();
    expect((await backendPost(token, sub)).status).toBe(401);
  });
  it("bad(同じ漏れ): alg=none のトークンでも、bob 名義の申込みが通る", async () => {
    (["D5 トークンの署名", "D10 発行元への問い合わせ", "D13 顧客の署名と内容の照合", "D15 署名の連鎖"] as DefName[]).forEach((g) => D[g]());
    const { sub, token } = await algNone();
    expect((await backendPost(token, sub)).status).toBe(200);
    expect(await recorded((r) => r.contract.customer === "bob")).toBe(true);
  });
});

// ======== R2 本人が承認していない申込みが、本人名義で通る ========
scenario(3, "R2 × A3: 偽造したトークン(本人を alice)で、alice の署名のない申込みを出す", {
  defenses: ["D5 トークンの署名", "D10 発行元への問い合わせ", "D13 顧客の署名と内容の照合", "D15 署名の連鎖"],
  prepare: async () => ({ sub: unsigned(alice.prepare(await offerFor(alice), "life-1000")), token: await forgedFor("alice", await claimsOf(alice)) }),
  attack: async ({ sub, token }) => backendPost(token, sub),
  harmed: async () => recorded((r) => r.contract.customer === "alice"),
});

scenario(4, "R2 × A4: 期限切れのトークンで、alice の署名のない申込みを出す", {
  defenses: ["D6 トークンの期限", "D10 発行元への問い合わせ", "D13 顧客の署名と内容の照合", "D15 署名の連鎖"],
  prepare: async () => {
    const routed = (await exchange("sales-agent", await alice.salesTicket(), "insurer-mcp")).access_token!;
    const stale = (await exchange("insurer-mcp", routed, "insurer-backend")).access_token!;
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 11 * 60_000 }); // トークンの 10 分を過ぎる
    return { sub: unsigned(alice.prepare(await offerFor(alice), "life-1000")), token: stale };
  },
  attack: async ({ sub, token }) => backendPost(token, sub),
  harmed: async () => recorded((r) => r.contract.customer === "alice"),
});

scenario(5, "R2 × A5: 別の用途のトークン(ID トークン)で、alice の署名のない申込みを出す", {
  defenses: ["D3 絞った発行", "D7 トークンの宛先", "D8 トークンの種類", "D11 本人確認の属性をトークンから読む", "D13 顧客の署名と内容の照合", "D15 署名の連鎖", "D16 取決め"],
  minimal: ["D3 絞った発行", "D8 トークンの種類", "D11 本人確認の属性をトークンから読む", "D13 顧客の署名と内容の照合", "D15 署名の連鎖", "D16 取決め"],
  prepare: async () => ({
    sub: unsigned(alice.prepare(await offerFor(alice), "life-1000")), claims: await claimsOf(alice), token: (await alice.tokens()).id_token,
  }),
  attack: async ({ sub, claims, token }) => backendPost(token, { ...sub, verified_claims: claims }),
  harmed: async () => recorded((r) => r.contract.customer === "alice"),
});

// ======== R3 本人確認の済んでいない人の申込みが通る ========
scenario(6, "R3 × A2: 本人確認の済んでいない mallory が、alice の確認結果を名乗って申し込む", {
  defenses: ["D11 本人確認の属性をトークンから読む"],
  prepare: async () => ({ sub: mallory.prepare(await offerFor(mallory), "med-light"), claims: await claimsOf(alice) }),
  attack: async ({ sub, claims }) => apply((await atMcp(mallory)).mcp, sub, { verified_claims: claims }),
  harmed: async () => recorded((r) => r.contract.customer === "mallory"),
}, () => {
  it("トークンには、確認の済んだ顧客だけに確認済みの属性が付く", async () => {
    expect((await claimsOf(alice)).verification.method).toBeTruthy();
    expect(await claimsOf(mallory)).toBeUndefined();
  });
});

// ======== R4 同意のない人が被保険者にされる ========
scenario(7, "R4 × A14: bob の同意なく、bob を被保険者にする", {
  defenses: ["D14 被保険者の署名"],
  prepare: async () => ({ sub: { ...alice.prepare(await offerFor(alice), "med-light", { insured: bob }), insuredAssertion: undefined } }),
  attack: async ({ sub }) => apply((await atMcp(alice)).mcp, sub),
  harmed: async () => recorded((r) => r.contract.insured === "bob"),
}, () => {
  it("good: bob になりすまして alice 自身が署名しても、bob のパスキーではないので弾かれる", async () => {
    const sub = alice.prepare(await offerFor(alice), "med-light", { insured: bob });
    const r = await apply((await atMcp(alice)).mcp, { ...sub, insuredAssertion: alice.sign(sub.application) });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("被保険者の署名");
  });
  it("good: bob 自身の署名があれば通る", async () => {
    const r = await apply((await atMcp(alice)).mcp, alice.prepare(await offerFor(alice), "med-light", { insured: bob }));
    expect(r.isError).toBe(false);
  });
});

// ======== R5 本人が選んだ内容と違う契約になる ========
// alice が「医療 ライト」に署名 → 乗っ取られた営業 AI エージェントが、取決めの範囲で最も保険料が高い案に書き換えて提出する
const viaTamperingAgent = async () => {
  salesConfig.tamper = true;
  const ticket = await alice.salesTicket();
  const auth = { authorization: `Bearer ${ticket}`, "content-type": "application/json" };
  const chat = (await (await fetch(`${urls.salesAgent}/chat`, { method: "POST", headers: auth, body: JSON.stringify({ message: "案を見たい" }) })).json()) as { offer: OfferResult };
  const sub = alice.prepare(chat.offer, "med-light");
  return fetch(`${urls.salesAgent}/submit`, { method: "POST", headers: auth, body: JSON.stringify({ ...sub, offerSet: chat.offer.offerSet }) });
};
scenario(8, "R5 × A8: 署名のあとで、保険料の高い案に書き換える", {
  defenses: ["D13 顧客の署名と内容の照合", "D15 署名の連鎖"],
  prepare: async () => ({}),
  attack: async () => viaTamperingAgent(),
  harmed: async () => recorded((r) => r.contract.plan.id === "life-1000"),
}, () => {
  it("bad(mTLS だけ): 通信相手は信頼できる MCP なので、書き換えも通る", async () => {
    setBackend({ seal: "mtls-only", chain: "none" });
    expect((await viaTamperingAgent()).status).toBe(200);
    expect(await recorded((r) => r.contract.plan.id === "life-1000")).toBe(true);
  });
  it("bad(AI 自身が署名): 書き換えた張本人が署名するので通る", async () => {
    setBackend({ seal: "agent-signed", chain: "none" });
    const { mcp } = await atMcp();
    const offer = await getOffer(mcp);
    const sub = alice.prepare(offer, "med-light");
    const tampered = { ...sub.application, plan: planOf(offer, "life-1000") };
    const jws = await new CompactSign(new TextEncoder().encode(canonical(tampered)))
      .setProtectedHeader({ alg: "ES256" }).sign(await importJWK(agentKey.priv, "ES256"));
    expect((await apply(mcp, { ...sub, application: tampered, assertion: jws })).isError).toBe(false);
    expect(await recorded((r) => r.contract.plan.id === "life-1000")).toBe(true);
  });
});

const GOLD: Plan = { id: "med-gold", name: "医療 ゴールド", kind: "medical", benefit: 100_000, monthly: 100 };
// 営業 AI エージェントが、本物の提示から nonce だけ取り、案を足した偽の提示を顧客に見せる。顧客のアプリが署名を確かめなければ、顧客は偽の案に署名する。
async function forgedOffer() {
  const offer = await offerFor(alice);
  const set: OfferSet = { customer: "alice", plans: [...offer.offerSet.plans, GOLD] };
  const key = (await generateKeyPair("ES256")).privateKey;
  return { offer, forged: { ...offer, offerSet: set, offerSetId: offerSetId(set), offerJws: await signOfferSet(key, "x", set, offer.nonce) } as OfferResult };
}
scenario(9, "R5 × A9: 保険会社が示していない案で申し込む", {
  defenses: ["D12 提示の署名"],
  prepare: async () => ({ sub: alice.prepare((await forgedOffer()).forged, "med-gold") }),
  attack: async ({ sub }) => apply((await atMcp(alice)).mcp, sub),
  harmed: async () => recorded((r) => r.contract.plan.id === "med-gold"),
}, () => {
  it("good: 本物の提示を添えても、その提示にない案なら弾かれる", async () => {
    const { offer, forged } = await forgedOffer();
    const r = await apply((await atMcp(alice)).mcp, alice.prepare({ ...forged, offerJws: offer.offerJws, offerSetId: offer.offerSetId }, "med-gold"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("案が提示に含まれる");
  });
});

scenario(10, "R5 × A10: 意向確認と申込みの間で、内容をすり替える", {
  defenses: ["D15 署名の連鎖"],
  // 顧客は「医療 ライト」の意向確認に署名したが、申込みは「死亡 1,000万円」に署名してしまった
  prepare: async () => {
    const offer = await offerFor(alice);
    const sub = alice.prepare(offer, "med-light");
    const application = { ...sub.application, plan: planOf(offer, "life-1000") };
    return { sub: { ...sub, application, assertion: alice.sign(application) } };
  },
  attack: async ({ sub }) => apply((await atMcp(alice)).mcp, sub),
  harmed: async () => recorded((r) => r.contract.plan.id === "life-1000"),
}, () => {
  it("good: 意向確認の署名がない申込みは弾かれる", async () => {
    const sub = alice.prepare(await offerFor(alice), "med-light");
    const r = await apply((await atMcp(alice)).mcp, { ...sub, intentAssertion: undefined });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("意向確認の署名");
  });
});

scenario(11, "R5 × A15: 申込みと違う内容で、契約を記録させる", {
  defenses: ["D18 記録の導出"],
  prepare: async () => {
    const offer = await offerFor(alice);
    return { sub: alice.prepare(offer, "med-light"), entry: { plan: planOf(offer, "life-3000") } };
  },
  attack: async ({ sub, entry }) => apply((await atMcp(alice)).mcp, sub, { contractEntry: entry }),
  harmed: async () => recorded((r) => r.contract.plan.id === "life-3000"),
}, () => {
  it("事後: 悪い実装で記録が食い違っても、顧客の自動照合が不一致に気づく", async () => {
    setBackend({ ingest: "manual" });
    const offer = await offerFor(alice);
    const sub = alice.prepare(offer, "med-light");
    await apply((await atMcp(alice)).mcp, sub, { contractEntry: { plan: planOf(offer, "life-3000") } });
    const rec = reconcile([sub.application], await noticesOf("alice"));
    expect(rec[0]).toMatchObject({ status: "mismatch" });
    expect(rec[0]!.diffs).toContain("案");
  });
  it("good: 記録は、署名済みの申込みから決まった規則で作られる", async () => {
    const sub = alice.prepare(await offerFor(alice), "med-light");
    await apply((await atMcp(alice)).mcp, sub);
    const c = (await backendState()).contracts[0]!.contract;
    expect(c).toEqual(deriveContract(sub.application));
    expect(c.contractId).toBe(`C-${challengeOf(sub.application).slice(0, 12)}`);
  });
});

// ======== R6 同じ申込みが二重に契約される ========
scenario(12, "R6 × A11: 署名済みの申込みを、二度出す", {
  defenses: ["D17 使い捨ての値"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "med-light") }),
  attack: async ({ sub }) => { const { mcp } = await atMcp(alice); await apply(mcp, sub); await apply(mcp, sub); },
  harmed: async () => (await backendState()).contracts.length >= 2,
});

// ======== R7 取決めの範囲外の契約が通る ========
scenario(13, "R7 × A12: 取決めの範囲外の案で申し込む", {
  defenses: ["D16 取決め"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "life-3000") }),
  attack: async ({ sub }) => apply((await atMcp(alice)).mcp, sub),
  harmed: async () => recorded((r) => r.contract.plan.id === "life-3000"),
}, () => {
  it("good: 取決めにない保険の種類は弾かれる", async () => {
    const { mcp } = await atMcp(alice, MEDICAL_ONLY);
    const r = await apply(mcp, alice.prepare(await getOffer(mcp), "life-1000"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("扱える保険の種類");
  });
  it("good(署名を見ない実装でも): 取決めがあれば、範囲外の案は止まる(被害の範囲が限られる)", async () => {
    setBackend({ seal: "none", chain: "none", offers: "none" });
    const { mcp } = await atMcp(alice, MEDICAL_ONLY);
    const offer = await getOffer(mcp);
    const sub = alice.prepare(offer, "med-light");
    const r = await apply(mcp, { ...sub, application: { ...sub.application, plan: planOf(offer, "life-3000") } });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("扱える保険の種類");
  });
});

scenario(14, "R7 × A17: トークンを替えるときに取決めを広げさせ、範囲外の案で申し込む", {
  defenses: ["D3 絞った発行"],
  prepare: async () => {
    const routed = (await exchange("sales-agent", await alice.salesTicket(), "insurer-mcp", { authorization_details: WIDE })).access_token!;
    return { routed, sub: alice.prepare(await offerFor(alice), "life-3000") };
  },
  attack: async ({ routed, sub }) => apply(await connectMcp(routed), sub),
  harmed: async () => recorded((r) => r.contract.plan.id === "life-3000"),
});

// ======== R8 権限のない者や経路から、申込みが通る ========
// 正規の経路(営業 AI エージェント → 事務サービス → 保険会社のシステム)を通らずに記録された契約は、経由の記録が欠ける
const offRoute = () => recorded((r) => r.by.join() !== FULL_ROUTE);
scenario(15, "R8 × A6: 営業 AI エージェントのためのトークンで、保険会社のシステムへ直接申し込む", {
  defenses: ["D7 トークンの宛先"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "med-light"), token: await alice.salesTicket() }),
  attack: async ({ sub, token }) => backendPost(token, sub),
  harmed: offRoute,
});

scenario(16, "R8 × A7: MCP が、受け取ったトークンをそのまま奥へ流して申し込む", {
  defenses: ["D2 MCP のトークンの交換(素通し)", "D7 トークンの宛先"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "med-light") }),
  attack: async ({ sub }) => apply((await atMcp(alice)).mcp, sub),
  harmed: offRoute,
});

scenario(17, "R8 × A7: 営業 AI エージェントのためのトークンを、MCP 経由で奥まで流して申し込む", {
  defenses: ["D1 MCP の宛先確認", "D2 MCP のトークンの交換(素通し)", "D7 トークンの宛先"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "med-light"), token: await alice.salesTicket() }),
  attack: async ({ sub, token }) => apply(await connectMcp(token), sub),
  harmed: offRoute,
});

scenario(18, "R8 × A17: どの窓口でも通るトークンで、保険会社のシステムへ直接申し込む", {
  defenses: ["D3 絞った発行"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "med-light"), token: await alice.salesTicket() }),
  attack: async ({ sub, token }) => backendPost(token, sub),
  harmed: offRoute,
}, () => {
  it("雑な発行は、有効期間も長い(盗まれたトークンが長く使える)", async () => {
    process.env.INSURER_MODE_AUTH = "bad";
    const p = payloadOf(await alice.salesTicket());
    expect(p.exp - p.iat).toBe(24 * 3600);
  });
});

scenario(19, "R8 × A13: 登録の外れた営業 AI が、出済みのトークンで申し込む", {
  defenses: ["D10 発行元への問い合わせ"],
  // トークンをもらい、案も受け取ったあとで、営業 AI エージェントの登録が外れる
  prepare: async () => {
    const { mcp } = await atMcp();
    const sub = alice.prepare(await getOffer(mcp), "med-light");
    await revokeClient("sales-agent");
    return { mcp, sub };
  },
  attack: async ({ mcp, sub }) => apply(mcp, sub),
  harmed: async () => (await backendState()).contracts.length > 0,
}, () => {
  it("登録が外れた営業 AI エージェントには、新しいトークンも出さない(D4)", async () => {
    const ticket = await alice.salesTicket();
    await revokeClient("sales-agent");
    expect((await exchange("sales-agent", ticket, "insurer-mcp")).access_token).toBeUndefined();
  });
  it("トークンの失効(RFC 7009)と有効性の問い合わせ(RFC 7662)", async () => {
    const { routed } = await atMcp();
    const basic = "Basic " + Buffer.from("insurer-backend:insurer-backend-secret").toString("base64");
    const ask = async () => ((await (await fetch(`${urls.insurerAuth}/introspect`, {
      method: "POST", headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: routed }),
    })).json()) as { active: boolean }).active;
    expect(await ask()).toBe(true);
    await fetch(`${urls.insurerAuth}/revoke`, {
      method: "POST", headers: { authorization: "Basic " + Buffer.from("sales-agent:sales-agent-secret").toString("base64"), "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: routed }),
    });
    expect(await ask()).toBe(false);
  });
});

// ======== R9 顧客が、届いた契約内容で照合できない(事後) ========
scenario(20, "R9 × A16: 契約内容の通知先を、営業 AI が書いた連絡先にする", {
  defenses: ["D19 登録済みの通知先"],
  prepare: async () => ({ sub: alice.prepare(await offerFor(alice), "med-light") }),
  attack: async ({ sub }) => apply((await atMcp(alice)).mcp, sub, { contact: "http://localhost:9/notices" }),
  harmed: async () => (await noticesOf("alice")).length === 0,
}, () => {
  it("事後: 通知が届かないことに、顧客の自動照合が気づく", async () => {
    setBackend({ notify: "from-application" });
    const sub = alice.prepare(await offerFor(alice), "med-light");
    await apply((await atMcp(alice)).mcp, sub, { contact: "http://localhost:9/notices" });
    expect(reconcile([sub.application], await noticesOf("alice"))[0]!.status).toBe("missing");
  });
  it("事後: 覚えのない通知(申し込んでいない契約)も、自動照合で見つかる", () => {
    const stray: Notice = { customer: "alice", contract: { contractId: "C-x", customer: "alice", insured: "alice", offerSetId: "x", nonce: "n-x", plan: { id: "p", name: "p", kind: "death", benefit: 1, monthly: 1 } } };
    expect(reconcile([], [stray])[0]).toMatchObject({ status: "unexpected" });
  });
});

// ======== R10 誰が取り次いだかを、後から追えない(事後) ========
scenario(21, "R10 × A17: 経由を残さない発行で、取り次いだ窓口が記録に残らない", {
  defenses: ["D3 絞った発行"],
  prepare: async () => {
    const { mcp } = await atMcp(alice);
    return { mcp, sub: alice.prepare(await getOffer(mcp), "med-light") };
  },
  attack: async ({ mcp, sub }) => apply(mcp, sub),
  harmed: offRoute,
});
