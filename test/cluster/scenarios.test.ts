// シナリオ: リスク × 手口 × 防御の漏れ（scenarios の 2〜3 章）。クラスタの secure と vulnerable で確かめる。
// 乗っ取られた営業 AI エージェントは、その ServiceAccount で動く probe が演じる（自分の SVID で A を B に替え、道具を直接呼ぶ）。
// 各シナリオで、(1) 防御が全てあれば被害が出ない（secure と vulnerable）、(2) 止める防御を 1 つずつ外しても、ほかの防御が止める、
// (3) 最小の漏れの組を外すと被害が出る（vulnerable）、を確かめる。シナリオ 4（期限切れ）は expiry.test.ts にある。
import { generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import { reconcile } from "../../packages/customer-app/src/reconcile.ts";
import {
  applyArgs, atMcp, auditOf, auditorGet, backendPost, checksOf, contractsOf, Customer, exchangeAs, ISSUER, LOGIN_ISSUER, mcpCall, offerFor, probe, publicOrigin, records,
  setDefenses, setTamper, TERMS, type Gaps, type Json, type Ns, type Offer, type Submission,
} from "./world.ts";

const FULL_ROUTE = ["insurer-mcp", "sales-agent"];
const WIDE = [{ type: "insurance_application", kinds: ["fixed", "lifetime"], maxBenefit: 100_000_000 }];
const FIXED_ONLY = [{ type: "insurance_application", kinds: ["fixed"], maxBenefit: 10_000_000 }];

// ---- 顧客（トークンの期限の前に、受け取り直す） ----
const cache = new Map<string, { at: number; c: Customer }>();
async function customer(ns: Ns, user: string, terms: unknown = TERMS): Promise<Customer> {
  const key = `${ns}:${user}:${JSON.stringify(terms)}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < 200_000) return hit.c;
  const c = await new Customer(ns, user).setup(terms);
  cache.set(key, { at: Date.now(), c });
  return c;
}

// ---- 防御（vulnerable で外す設定） ----
const D = {
  G1: { G1: "off" },
  "G2 素通し": { G2: "passthrough" },
  "G2 自分の資格": { G2: "client-credentials" },
  G3a: { G3a: "off" },
  G3c: { G3c: "off" },
  G3d: { G3d: "off" },
  G3e: { G3e: "off" },
  G3f: { G3f: "off" },
  G5: { G5: "off" },
  G7: { G7: "off" },
  G8: { G8: "off" },
  G9: { G9: "off" },
  G10: { G10: "off" },
  G11: { G11: "off" },
  G12: { G12: "off" },
  G13: { G13: "off" },
  G14: { G14: "off" },
  G15: { G15: "off" },
  G16: { G16: "off" },
  G17: { G17: "off" },
  G18: { G18: "off" },
  G30: { G30: "off" },
  "G26 営業 AI エージェント": { "G26@sales-agent": "off" },
  "G26 事務サービス": { "G26@insurer-mcp": "off" },
  "G26 保険会社のシステム": { "G26@insurer-backend": "off" },
  G28: { G28: "off" },
  "G29 事務サービス": { "G29@insurer-mcp": "off" },
  "G29 保険会社のシステム": { "G29@insurer-backend": "off" },
  "G27 事務サービス": { "G27@insurer-mcp": "off" },
  "G27 保険会社のシステム": { "G27@insurer-backend": "off" },
} satisfies Record<string, Gaps>;
type DefName = keyof typeof D;
const gapsOf = (names: DefName[]): Gaps => Object.assign({}, ...names.map((n) => D[n]));

afterEach(async () => {
  await setDefenses({});
  await setTamper(false);
});

// ---- シナリオの型 ----
// defenses: どれか 1 つでもあれば被害が出ない防御。minimal: 被害が出るのに外す必要がある防御（省略時は defenses 全部）。
function scenario<C>(
  n: number,
  title: string,
  s: {
    defenses: DefName[];
    minimal?: DefName[];
    prepare: (ns: Ns) => Promise<C>;
    attack: (ns: Ns, c: C) => Promise<unknown>;
    harmed: (ns: Ns, c: C) => Promise<boolean>;
    secure?: false;
  },
  extra?: () => void,
) {
  describe(`${n}. ${title}`, () => {
    // 攻撃の材料は、防御を全て入れたまま準備する。外すのは、攻撃の直前である
    const run = async (ns: Ns, gaps: DefName[]) => {
      const c = await s.prepare(ns);
      if (ns === "vulnerable") await setDefenses(gapsOf(gaps));
      await s.attack(ns, c).catch(() => undefined); // 途中で拒否されても、被害の有無で判定する
      return s.harmed(ns, c);
    };
    if (s.secure !== false) it("secure: 防御が全てあれば、被害は出ない", async () => expect(await run("secure", [])).toBe(false));
    it(`vulnerable（${s.defenses.join("、")} が全てある）: 被害は出ない`, async () => expect(await run("vulnerable", [])).toBe(false));
    if (s.defenses.length > 1) {
      for (const d of s.defenses) {
        it(`vulnerable（${d} だけを外す）: ほかの防御が止める`, async () => expect(await run("vulnerable", [d])).toBe(false));
      }
    }
    const min = s.minimal ?? s.defenses;
    it(`vulnerable（${min.join("、")} を外す）: 被害が出る`, async () => expect(await run("vulnerable", min)).toBe(true));
    extra?.();
  });
}

// ---- 補助 ----
const submitViaMcp = async (ns: Ns, token: string, s: Submission, extras?: Json) =>
  mcpCall(ns, token, "submit_application", applyArgs(s, extras));
const unsigned = (s: Submission): Submission => ({ ...s, assertion: null, intentAssertion: null });
const planOf = (offer: Offer, id: string) => offer.offerSet.plans.find((p) => p.id === id)!;
const decode = (token: string) => JSON.parse(Buffer.from(token.split(".")[1]!, "base64url").toString()) as Json;
const recorded = async (ns: Ns, nonce: string, pred: (c: Json) => boolean = () => true) => (await contractsOf(ns, nonce)).some(pred);
const offRoute = (c: Json) => JSON.stringify(c.by) !== JSON.stringify(FULL_ROUTE);

/** ログインサーバーの鍵ではない鍵で署名した、偽の A。形は、本物と同じである。 */
async function forgedA(ns: Ns, sub: string, verified: unknown) {
  const { privateKey } = await generateKeyPair("RS256");
  return new SignJWT({ azp: "customer-app", scope: "openid apply", authorization_details: TERMS, verified_claims: verified, may_act: { iss: ISSUER(ns), sub: "sales-agent" } })
    .setProtectedHeader({ alg: "RS256", kid: "forged", typ: "at+jwt" })
    .setIssuer(LOGIN_ISSUER(ns))
    .setSubject(sub)
    .setAudience("sales-agent")
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

/** 保険会社の鍵ではない鍵で署名した、偽造トークン。結び付けは、出す probe の証明書に合わせる。 */
async function forged(ns: Ns, sub: string, verified: unknown) {
  const { privateKey } = await generateKeyPair("RS256");
  const { x5t } = await probe(ns, "probe-mcp-1", "whoami");
  return new SignJWT({ scope: ["apply"], authorization_details: TERMS, verified_claims: verified, act: { sub: "insurer-mcp", act: { sub: "sales-agent" } }, cnf: { "x5t#S256": x5t } })
    .setProtectedHeader({ alg: "RS256", kid: "forged", typ: "at+jwt" })
    .setIssuer(ISSUER(ns))
    .setSubject(sub)
    .setAudience("insurer-backend")
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}

// ======== R1 他人名義の申込みが通る ========
scenario(1, "R1 × A1: 営業 AI エージェントが欄に「bob」と書き、bob 名義で申し込む", {
  defenses: ["G2 自分の資格", "G9", "G11", "G13", "G14"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(await customer(ns, "bob"));
    const sub = alice.prepare(offer, "fixed-60");
    return { alice, sub: unsigned({ ...sub, application: { ...sub.application, customer: "bob" }, intent: { ...sub.intent, customer: "bob" } }), offer };
  },
  attack: async (ns, { alice, sub }) =>
    submitViaMcp(ns, await atMcp(alice), sub, { verified_claims: decode(alice.token).verified_claims }),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, (c) => c.contract.customer === "bob"),
}, () => {
  it("secure: 替えたトークンには、本人（sub）が残り、取り次いだ営業 AI エージェントが act に積まれる", async () => {
    const b = decode(await atMcp(await customer("secure", "alice")));
    expect(b.sub).toBe("alice");
    expect(b.act.sub).toBe("sales-agent");
  });
});

scenario(2, "R1 × A3: 偽造したトークンで、bob 名義の申込みを、保険会社のシステムへ直接出す", {
  defenses: ["G5", "G10", "G13", "G14"],
  prepare: async (ns) => {
    const bob = await customer(ns, "bob");
    const offer = await offerFor(bob);
    return { offer, sub: unsigned(bob.prepare(offer, "fixed-60")), token: await forged(ns, "bob", decode(bob.token).verified_claims) };
  },
  attack: async (ns, { sub, token }) => backendPost(ns, token, sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
}, () => {
  it("secure: 署名のない（alg=none）トークンは受け付けない", async () => {
    const b = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const none = `${b({ alg: "none", typ: "at+jwt" })}.${b({ iss: ISSUER("secure"), sub: "alice", aud: "insurer-backend", exp: 4102444800 })}.`;
    expect((await backendPost("secure", none, {})).status).toBe(401);
  });
});

scenario(3, "R2 × A3: 偽造したトークンで、本人の知らない申込みを出す", {
  defenses: ["G5", "G10", "G13", "G14"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    return { offer, sub: unsigned(alice.prepare(offer, "fixed-60")), token: await forged(ns, "alice", decode(alice.token).verified_claims) };
  },
  attack: async (ns, { sub, token }) => backendPost(ns, token, sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
});

scenario(5, "R2 × A5: 顧客の ID トークンを、申込みのトークンとして使う", {
  defenses: ["G3c", "G7", "G8", "G10", "G11", "G13", "G14", "G15", "G26 保険会社のシステム", "G29 保険会社のシステム"],
  minimal: ["G3c", "G8", "G10", "G11", "G13", "G14", "G15", "G26 保険会社のシステム", "G29 保険会社のシステム"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    return { alice, offer, sub: unsigned(alice.prepare(offer, "fixed-60")) };
  },
  // 発行の防御（G3c）が効くのは、ID トークンを受け取るときなので、受け取りから攻撃に含める
  attack: async (ns, { alice, sub }) =>
    backendPost(ns, (await new Customer(ns, "alice").setup()).idToken, { ...sub, verified_claims: decode(alice.token).verified_claims }),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
});

// ======== R3 本人確認の済んでいない人の申込みが通る ========
scenario(6, "R3 × A2: 本人確認の済んでいない mallory が、alice の確認結果を名乗って申し込む", {
  defenses: ["G11"],
  prepare: async (ns) => {
    const mallory = await customer(ns, "mallory");
    const offer = await offerFor(mallory);
    return { mallory, offer, sub: mallory.prepare(offer, "fixed-60"), claims: decode((await customer(ns, "alice")).token).verified_claims };
  },
  attack: async (ns, { mallory, sub, claims }) => submitViaMcp(ns, await atMcp(mallory), sub, { verified_claims: claims }),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
}, () => {
  it("secure: トークンには、確認の済んだ顧客だけに確認済みの属性が付く", async () => {
    expect(decode((await customer("secure", "alice")).token).verified_claims.verification.method).toBeTruthy();
    expect(decode((await customer("secure", "mallory")).token).verified_claims).toBeUndefined();
  });
});

// ======== R4 本人が選んだ内容と違う契約になる ========
// alice が「確定年金 10年・年額60万円」に署名 → 乗っ取られた営業 AI エージェントが、取決めの範囲で最も保険料が高い案に書き換えて出す
scenario(7, "R4 × A8: 営業 AI エージェントが、署名のあとで申込みの内容を書き換える", {
  defenses: ["G13", "G14"],
  // secure には、書き換えを再現する受け口がない（D-24）
  secure: false,
  prepare: async (ns) => ({ alice: await customer(ns, "alice") }),
  // 顧客は確定年金 60 万円を選んで 2 つの書類に署名する。乗っ取られた営業 AI エージェントは、提出の直前に書き換える
  attack: async (_ns, { alice }) => {
    await setTamper(true);
    const r = await alice.converse("fixed-60");
    (alice as Customer & { last?: string }).last = r.nonce;
  },
  harmed: async (ns, { alice }) => recorded(ns, (alice as Customer & { last?: string }).last!, (c) => c.contract.plan.id !== "fixed-60"),
}, () => {
  it("vulnerable: 信頼する事務サービス（mTLS）から届いたことだけで受け付けると、書き換えが通る", async () => {
    await setDefenses({ G13: "mtls-only", G14: "off" });
    const alice = await customer("vulnerable", "alice");
    await setTamper(true);
    const { nonce } = await alice.converse("fixed-60");
    expect(await recorded("vulnerable", nonce, (c) => c.contract.plan.id !== "fixed-60")).toBe(true);
  });
});

const GOLD = { id: "fixed-gold", name: "確定年金・特別", kind: "fixed", benefit: 600_000, monthly: 1_000 };
async function forgedOffer(alice: Customer) {
  const offer = await offerFor(alice);
  const { privateKey } = await generateKeyPair("ES256");
  const plans = [...offer.offerSet.plans, GOLD];
  const { challengeOf } = await import("./probe/webauthn.ts");
  const offerSetId = challengeOf({ customer: "alice", plans });
  const offerJws = await new SignJWT({ customer: "alice", plans, offerSetId, nonce: offer.nonce })
    .setProtectedHeader({ alg: "ES256", kid: "x", typ: "offer+jwt" })
    .setIssuer("insurer-backend")
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
  return { offer, forged: { ...offer, offerSet: { customer: "alice", plans }, offerSetId, offerJws } };
}

// シナリオ 26、27: 営業 AI エージェントが組み立てた案を、保険会社のシステムが確かめずに署名すると、顧客に偽の内容を示せる
const issueScenario = (plan: Json) => ({
  defenses: ["G30"] as DefName[],
  prepare: async (ns: Ns) => ({ alice: await customer(ns, "alice"), issued: {} as Json }),
  attack: async (ns: Ns, c: { alice: Customer; issued: Json }) => {
    c.issued.result = await mcpCall(ns, await atMcp(c.alice), "issue_offer", { plans: [plan] });
  },
  harmed: async (_ns: Ns, c: { issued: Json }) => Boolean(c.issued.result?.body?.offerJws),
});
scenario(26, "R4 × A22 保険料を安く書き換えた案に、署名させる", issueScenario({ kind: "fixed", monthly: 1_000, benefit: 600_000 }));
scenario(27, "R4 × A23 商品の規則の外の案に、署名させる", issueScenario({ kind: "lump-sum", monthly: 20_000, benefit: 600_000 }));

// シナリオ 8（R4 × A9）は、顧客のアプリの G22 と合わせて、画面のテスト（test/ui/scenarios.test.ts）で確かめる
describe("8 の補足（保険会社のシステムの G12）", () => {
  it("secure: 本物の提示を添えても、その提示にない案なら弾かれる", async () => {
    const alice = await customer("secure", "alice");
    const { offer, forged: f } = await forgedOffer(alice);
    const r = await submitViaMcp("secure", await atMcp(alice), alice.prepare({ ...f, offerJws: offer.offerJws, offerSetId: offer.offerSetId }, "fixed-gold"));
    expect(JSON.stringify(r.body)).toContain("案が提示に含まれる");
  });
});

scenario(9, "R4 × A10: 意向確認と申込みの間で、内容をすり替える", {
  defenses: ["G14"],
  // 顧客は「確定年金 10年・年額60万円」の意向確認に署名したが、申込みは「終身年金・年額120万円」に署名してしまった
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    const sub = alice.prepare(offer, "fixed-60");
    const application = { ...sub.application, plan: planOf(offer, "life-120") };
    return { alice, offer, sub: { ...sub, application, assertion: alice.sign(application) } };
  },
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, await atMcp(alice), sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, (c) => c.contract.plan.id === "life-120"),
}, () => {
  it("secure: 意向確認の署名がない申込みは弾かれる", async () => {
    const alice = await customer("secure", "alice");
    const sub = alice.prepare(await offerFor(alice), "fixed-60");
    const r = await submitViaMcp("secure", await atMcp(alice), { ...sub, intentAssertion: null });
    expect(JSON.stringify(r.body)).toContain("意向確認の署名");
  });
});

scenario(10, "R4 × A14: 申込みと違う内容で、契約を記録させる", {
  defenses: ["G17"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    return { alice, offer, sub: alice.prepare(offer, "fixed-60") };
  },
  attack: async (ns, { alice, offer, sub }) => submitViaMcp(ns, await atMcp(alice), sub, { contractEntry: { plan: planOf(offer, "life-240") } }),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, (c) => c.contract.plan.id === "life-240"),
}, () => {
  it("vulnerable: 事後に、顧客の自動照合が、通知と写しの食い違いに気づく", async () => {
    await setDefenses({ G17: "off" });
    const alice = await customer("vulnerable", "alice");
    const offer = await offerFor(alice);
    const sub = alice.prepare(offer, "fixed-60");
    await submitViaMcp("vulnerable", await atMcp(alice), sub, { contractEntry: { plan: planOf(offer, "life-240") } });
    const mine = reconcile([sub.application as never], (await alice.notices()) as never).filter((r) => r.nonce === offer.nonce);
    expect(mine[0]?.status).toBe("mismatch");
  });

  it("vulnerable: 事後に、監査サービスが、契約の案と取り次いだ申込みの案の食い違いを示す（G25）", async () => {
    await setDefenses({ G17: "off" });
    const alice = await customer("vulnerable", "alice");
    const offer = await offerFor(alice);
    await submitViaMcp("vulnerable", await atMcp(alice), alice.prepare(offer, "fixed-60"), { contractEntry: { plan: planOf(offer, "life-240") } });
    const report = await auditOf("vulnerable", offer.nonce, (r) => r.tool !== null && r.contractRecord !== null);
    expect(report.status).toBe("食い違いあり");
    expect(checksOf(report)).toMatchObject({ 申込みの中身: false, トークンの連鎖: true, 事務サービスの記録: true });
  });
});

scenario(11, "R5 × A11: 同じ申込みを二度出す", {
  defenses: ["G16"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    return { alice, offer, sub: alice.prepare(offer, "fixed-60") };
  },
  attack: async (ns, { alice, sub }) => {
    const b = await atMcp(alice);
    await submitViaMcp(ns, b, sub);
    return submitViaMcp(ns, b, sub);
  },
  harmed: async (ns, { offer }) => (await contractsOf(ns, offer.nonce)).length >= 2,
});

// ======== R6 取決めの範囲外の契約が通る ========
scenario(12, "R6 × A12: 取決めの上限を超える案で申し込む", {
  defenses: ["G15"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    return { alice, offer, sub: alice.prepare(offer, "life-240") };
  },
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, await atMcp(alice), sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
}, () => {
  it("secure: 取決めにない種類の案は弾かれる", async () => {
    const alice = await customer("secure", "alice", FIXED_ONLY);
    const sub = alice.prepare(await offerFor(alice), "life-120");
    expect(JSON.stringify((await submitViaMcp("secure", await atMcp(alice), sub)).body)).toContain("扱える保険の種類");
  });
});

scenario(13, "R6 × A16: 替えるときに、取決めを広げてもらう", {
  defenses: ["G3e"],
  prepare: async (ns) => {
    const alice = await customer(ns, "alice");
    const offer = await offerFor(alice);
    return { alice, offer, sub: alice.prepare(offer, "life-240") };
  },
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, await atMcp(alice, WIDE), sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
});

// ======== R7 権限のない者や経路から、申込みが通る ========
const signedFor = async (ns: Ns) => {
  const alice = await customer(ns, "alice");
  const offer = await offerFor(alice);
  return { alice, offer, sub: alice.prepare(offer, "fixed-60") };
};

scenario(14, "R7 × A6: 営業 AI エージェント宛ての A で、保険会社のシステムへ直接申し込む", {
  defenses: ["G7", "G10", "G26 保険会社のシステム", "G29 保険会社のシステム"],
  prepare: signedFor,
  attack: async (ns, { alice, sub }) => backendPost(ns, alice.token, sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, offRoute),
}, () => {
  it("vulnerable: 事後に、監査サービスが、事務サービスの記録の欠けと、トークンの連鎖の切れを示す（G25）", async () => {
    const { alice, offer, sub } = await signedFor("vulnerable");
    await setDefenses(gapsOf(["G7", "G10", "G26 保険会社のシステム", "G29 保険会社のシステム"]));
    await backendPost("vulnerable", alice.token, sub);
    const report = await auditOf("vulnerable", offer.nonce, (r) => r.contractRecord !== null && r.chain.length > 0);
    expect(report.status).toBe("食い違いあり");
    expect(checksOf(report)).toMatchObject({ 事務サービスの記録: false, トークンの連鎖: false });
  });
});

scenario(15, "R7 × A7: 事務サービスが、受け取った B をそのまま保険会社のシステムへ流す", {
  defenses: ["G2 素通し", "G7", "G26 保険会社のシステム"],
  prepare: signedFor,
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, await atMcp(alice), sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, offRoute),
});

scenario(16, "R7 × A7: 営業 AI エージェントが、A を事務サービスへそのまま出す", {
  defenses: ["G1", "G26 事務サービス", "G29 事務サービス", "G2 素通し", "G7", "G10", "G26 保険会社のシステム", "G29 保険会社のシステム"],
  prepare: signedFor,
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, alice.token, sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, offRoute),
});

scenario(17, "R7 × A16: どの窓口でも通る A で、保険会社のシステムへ直接申し込む", {
  defenses: ["G3a", "G10", "G26 保険会社のシステム", "G29 保険会社のシステム"],
  prepare: signedFor,
  // 発行の防御（G3a）が効くのは、トークンを受け取るときなので、受け取りから攻撃に含める
  attack: async (ns, { sub }) => backendPost(ns, (await new Customer(ns, "alice").setup()).token, sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, offRoute),
}, () => {
  it("vulnerable: 短い有効期間を外すと、24 時間使えるトークンが出る（G3b）", async () => {
    await setDefenses({ G3b: "off" });
    const t = decode((await new Customer("vulnerable", "alice").setup()).token);
    expect(t.exp - t.iat).toBeGreaterThan(3600);
  });
});

scenario(18, "R7 × A13: 登録が外れた営業 AI エージェントが取り次いだ申込みを出す", {
  defenses: ["G10"],
  prepare: async (ns) => ({ ...(await signedFor(ns)), b: "" }),
  attack: async (ns, c) => {
    c.b = await atMcp(c.alice);
    await probe(ns, "probe-operator", "operator", { action: "revoke", client: "sales-agent" });
    try {
      return await submitViaMcp(ns, c.b, c.sub);
    } finally {
      await probe(ns, "probe-operator", "operator", { action: "restore", client: "sales-agent" });
    }
  },
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce),
}, () => {
  it("secure: 登録が外れた営業 AI エージェントには、新しいトークンを出さない（G4）", async () => {
    await probe("secure", "probe-operator", "operator", { action: "revoke", client: "sales-agent" });
    try {
      const r = await probe("secure", "probe-sales-agent", "client-credentials");
      expect(r.status, JSON.stringify(r)).toBe(401);
    } finally {
      await probe("secure", "probe-operator", "operator", { action: "restore", client: "sales-agent" });
    }
  });
  it("secure: 登録を外せるのは、運用の担当だけである", async () => {
    const r = await probe("secure", "probe-intruder", "operator", { action: "revoke", client: "sales-agent" });
    expect(r.status, JSON.stringify(r)).toBe(403);
  });
});

// ======== R8 顧客が、届いた契約内容で照合できない（事後） ========
scenario(19, "R8 × A15: 契約内容の通知先を、営業 AI エージェントが書いた連絡先にする", {
  defenses: ["G18"],
  prepare: signedFor,
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, await atMcp(alice), sub, { contact: "http://attacker.invalid/notices" }),
  harmed: async (_ns, { alice, offer }) => !(await alice.notices()).some((n) => n.contract.nonce === offer.nonce),
}, () => {
  it("vulnerable: 事後に、通知が届かないことに、顧客の自動照合が気づく", async () => {
    await setDefenses({ G18: "off" });
    const { alice, offer, sub } = await signedFor("vulnerable");
    await submitViaMcp("vulnerable", await atMcp(alice), sub, { contact: "http://attacker.invalid/notices" });
    const mine = reconcile([sub.application as never], (await alice.notices()) as never).filter((r) => r.nonce === offer.nonce);
    expect(mine[0]?.status).toBe("missing");
  });
});

// ======== R9 誰が取り次いだかを、後から追えない（事後） ========
scenario(20, "R9 × A16: 経由を残さない発行で、取り次いだ窓口が記録に残らない", {
  defenses: ["G3d"],
  prepare: signedFor,
  attack: async (ns, { alice, sub }) => submitViaMcp(ns, await atMcp(alice), sub),
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, offRoute),
}, () => {
  it("vulnerable: 事後に、監査サービスが、契約の記録の経由と交換の記録の道の食い違いを示す（G25）", async () => {
    const { alice, offer, sub } = await signedFor("vulnerable");
    await setDefenses({ G3d: "off" });
    await submitViaMcp("vulnerable", await atMcp(alice), sub);
    const report = await auditOf("vulnerable", offer.nonce, (r) => r.contractRecord !== null && r.chain.length === 3);
    expect(report.status).toBe("食い違いあり");
    expect(checksOf(report)).toMatchObject({ 経由: false, トークンの連鎖: true });
  });
});

scenario(21, "R7 × A17: 営業 AI エージェントが、事務サービスを飛ばした宛先のトークンを求めて、直接申し込む", {
  defenses: ["G3f", "G27 保険会社のシステム"],
  prepare: signedFor,
  attack: async (ns, { alice, sub }) => {
    const c = await exchangeAs(ns, "probe-sales-agent", alice.token, "insurer-backend");
    return backendPost(ns, c.body?.access_token, sub, "probe-sales-agent");
  },
  harmed: async (ns, { offer }) => recorded(ns, offer.nonce, offRoute),
});

// ======== 発行者をまたぐ交換: 認可サーバーが、ログインサーバーの A を確かめて替える（D-36） ========
scenario(25, "R1 × A21: ログインサーバーを名乗って偽の A を作り、bob の代理のトークンに替えさせる", {
  defenses: ["G28"],
  prepare: async (ns) => ({ verified: decode((await customer(ns, "bob")).token).verified_claims, sub: undefined as unknown }),
  attack: async (ns, c) => {
    const b = await exchangeAs(ns, "probe-sales-agent", await forgedA(ns, "bob", c.verified), "insurer-mcp");
    c.sub = b.body?.access_token ? decode(b.body.access_token).sub : undefined;
  },
  harmed: async (_ns, c) => c.sub === "bob",
}, () => {
  for (const [name, off] of [["secure", false], ["vulnerable", true]] as const) {
    it(`${name}: ID トークンを替えに出しても、${off ? "G28 を外しても、" : ""}B は出ない（宛先と代理の認可で止まる）`, async () => {
      const ns = name;
      const alice = await new Customer(ns, "alice").setup();
      if (off) await setDefenses(gapsOf(["G28"]));
      expect((await exchangeAs(ns, "probe-sales-agent", alice.idToken, "insurer-mcp")).body?.access_token).toBeUndefined();
    });
  }
});

// ======== R10 本人の契約の情報が、本人以外に漏れる ========
scenario(22, "R10 × A18: 盗んだ A を、DPoP の鍵なしで使い、契約を照会させる", {
  defenses: ["G26 営業 AI エージェント"],
  prepare: async (ns) => ({ alice: await customer(ns, "alice"), r: {} as Json }),
  attack: async (_ns, c) => {
    const input = { threadId: crypto.randomUUID(), runId: crypto.randomUUID(), messages: [{ id: "m1", role: "user", content: "契約の一覧を見せて" }], tools: [], state: {}, context: [], forwardedProps: {} };
    c.r = await c.alice.agui(input, "none");
  },
  harmed: async (_ns, { r }) => r.status === 200 && /契約は \d+ 件/.test(String(r.body)),
});

scenario(23, "R10 × A19: 盗んだ B を、別のサービスの SVID で使い、契約を照会する", {
  defenses: ["G26 事務サービス", "G27 事務サービス"],
  prepare: async (ns) => ({ b: await atMcp(await customer(ns, "alice")), r: {} as Json }),
  attack: async (ns, c) => (c.r = await mcpCall(ns, c.b, "list_contracts", {}, "probe-intruder")),
  harmed: async (_ns, { r }) => r.status === 200 && Array.isArray(r.body?.contracts),
});

// ======== 補足: シナリオにしない防御と、隔たり ========
// ======== 監査サービス（G25）: 事後に、契約ごとに、自己申告と第三者の記録を突き合わせる ========
describe("監査サービス（G25）", () => {
  it("secure: 正規の契約は、食い違いなしで、認可サーバー、事務サービス、保険会社のシステムの記録がそろう", async () => {
    const { alice, offer, sub } = await signedFor("secure");
    await submitViaMcp("secure", await atMcp(alice), sub);
    const report = await auditOf("secure", offer.nonce, (r) => r.ok === true);
    expect(report.status, JSON.stringify(report.checks)).toBe("食い違いなし");
    expect(report.chain.map((r: Json) => r.kind)).toEqual(["exchange", "exchange", "issue"]);
    expect(report.tool?.application_hash).toBe(report.contractRecord?.application_hash);
    expect(report.selfReport?.tokenJti).toBe(report.contractRecord?.token_jti);
    // 何と何を比べたかが、書いた者つきで示され、判定と食い違わない
    const compared = (report.checks as Json[]).flatMap((c) => c.comparisons as Json[]);
    expect(compared.find((v) => v.what === "案")).toMatchObject({ left: "fixed-60", leftBy: "保険会社のシステム", right: "fixed-60", rightBy: "事務サービス", ok: true });
    expect(compared.every((v) => v.ok)).toBe(true);
  });

  it("secure: 監査の担当でない者（顧客）は、ログインできても、監査の記録を読めない", async () => {
    expect((await auditorGet("secure", "/api/contracts", "alice")).status).toBe(403);
    expect((await auditorGet("secure", "/api/contracts")).status).toBe(200);
  });

  it("vulnerable: 営業 AI エージェントが、認可サーバーを名乗って書いた交換の記録は、受け付けない（D-32）", async () => {
    await setDefenses({});
    const { alice, offer, sub } = await signedFor("vulnerable");
    await submitViaMcp("vulnerable", await atMcp(alice), sub);
    const before = await auditOf("vulnerable", offer.nonce, (r) => r.ok === true);
    expect(before.status, JSON.stringify(before.checks)).toBe("食い違いなし");
    // 乗っ取られた営業 AI エージェントが、C と同じ jti で、経由を偽った交換の記録を書く
    const forged = { kind: "exchange", service: "insurer-auth", client: "insurer-mcp", sub: "alice", jti: before.contractRecord.token_jti, from_jti: "forged", act: { sub: "insurer-mcp" } };
    await probe("vulnerable", "probe-intruder", "admin", { service: "sales-agent", port: 9091, path: "/forge-audit", method: "PUT", body: forged });
    const after = await auditOf("vulnerable", offer.nonce, (r) => r.rejected.length > 0);
    expect(after.rejected.map((r: Json) => [r.kind, r.app])).toEqual([["exchange", "sales-agent"]]);
    // 連鎖は、認可サーバーが書いた記録だけでたどる
    expect(checksOf(after)).toMatchObject({ トークンの連鎖: true, 経由: true, 書いた者: false });
    expect(after.chain[0].from_jti).toBe(before.chain[0].from_jti);
  });
});

describe("補足: passkey（G13。D-42）", () => {
  it("secure: ログインと同じ passkey で申込みに署名でき、保険会社のシステムは、ログインサーバーにある公開鍵で確かめる", async () => {
    const alice = await new Customer("secure", "alice").setup();
    const offer = await offerFor(alice);
    const r = await mcpCall("secure", await atMcp(alice), "submit_application", applyArgs(alice.prepare(offer, "fixed-60")));
    expect(r.body?.ok, JSON.stringify(r)).toBe(true);
  });

  it("secure: ログインの画面の名前で作った署名は、申込みの署名として受け付けない（ログインの署名の使い回しを防ぐ）", async () => {
    const alice = await new Customer("secure", "alice").setup();
    const offer = await offerFor(alice);
    const sub = alice.prepare(offer, "fixed-60");
    const fromLogin = { ...sub, assertion: alice.sign(sub.application, publicOrigin("secure", "login")) };
    const r = await mcpCall("secure", await atMcp(alice), "submit_application", applyArgs(fromLogin));
    // 鍵と内容は正しいので、断る理由は、署名した画面（origin）だけである
    expect(r.body?.error ?? "", JSON.stringify(r)).toContain("申込みの署名の照合: 顧客のアプリの画面で作った署名ではない");
  });
});

describe("補足: ログインの更新（G31。P-18、D-41）", () => {
  it("secure: 更新した A は、中身を保ち、B と C は呼び出しの間だけ有効である", async () => {
    const alice = await new Customer("secure", "alice").setup();
    const before = decode(alice.token);
    expect((await alice.refresh()).status).toBe(200);
    const after = decode(alice.token);
    expect(after.jti).not.toBe(before.jti);
    for (const claim of ["sub", "aud", "cnf", "may_act", "verified_claims", "authorization_details"]) expect(after[claim]).toEqual(before[claim]);
    expect(after.exp - after.iat).toBe(300);
    const b = decode(await atMcp(alice));
    expect(b.exp - b.iat).toBe(60);
  });

  it("secure: 顧客のアプリのクライアント認証のない更新は、断られる（盗んだ更新のトークンだけでは使えない）", async () => {
    const alice = await new Customer("secure", "alice").setup();
    expect((await alice.refresh("good", alice.refreshToken, true)).status).toBe(401);
    expect((await alice.refresh()).status).toBe(200);
  });

  it("secure: 営業 AI エージェントは、顧客のアプリの BFF からだけ受ける（G27。D-41）。正しい A と proof でも、ほかの身元からは断る", async () => {
    const alice = await customer("secure", "alice");
    const input = { threadId: crypto.randomUUID(), runId: crypto.randomUUID(), messages: [{ id: "m1", role: "user", content: "見たい" }], tools: [], state: {}, context: [], forwardedProps: {} };
    const other = await probe("secure", "probe-sales-agent", "call-sales-agent", { path: "/agui", body: input, token: alice.token, dpopKey: alice.dpopKey });
    expect(other.status).toBe(403);
  });

  it("secure: 更新のトークンを使い回すと断られ、最新のものも使えなくなる", async () => {
    const alice = await new Customer("secure", "alice").setup();
    const stolen = alice.refreshToken;
    expect((await alice.refresh()).status).toBe(200);
    expect((await alice.refresh("good", stolen)).status).toBe(400);
    expect((await alice.refresh()).status).toBe(400);
  });

  it("secure: 更新した A で申し込んでも、監査は食い違いを示さない", async () => {
    const alice = await new Customer("secure", "alice").setup();
    expect((await alice.refresh()).status).toBe(200);
    const offer = await offerFor(alice);
    const sub = alice.prepare(offer, "fixed-60");
    const r = await mcpCall("secure", await atMcp(alice), "submit_application", applyArgs(sub));
    expect(r.body?.ok, JSON.stringify(r)).toBe(true);
    const report = await auditOf("secure", offer.nonce, (x) => x.contractRecord !== null && x.chain.length === 3);
    expect(report.status, JSON.stringify(report)).toBe("食い違いなし");
  });
});

describe("補足", () => {
  it("secure: A はログインサーバーが出し、B は認可サーバーが、顧客と経由を保ったまま出す（D-35）", async () => {
    const alice = await customer("secure", "alice");
    const a = decode(alice.token);
    const b = decode(await atMcp(alice));
    expect(a.iss).toBe(LOGIN_ISSUER("secure"));
    expect(b.iss).toBe(ISSUER("secure"));
    expect([a.sub, a.aud, a.authorization_details?.[0].maxBenefit]).toEqual(["alice", "sales-agent", TERMS[0]!.maxBenefit]);
    expect([b.sub, b.aud, b.act.sub, b.authorization_details[0].maxBenefit]).toEqual(["alice", "insurer-mcp", "sales-agent", TERMS[0]!.maxBenefit]);
  });

  it("secure: 営業 AI エージェントは、自分宛てでないトークン（B）を受け付けない（G20）", async () => {
    const alice = await customer("secure", "alice");
    const b = await atMcp(alice);
    const input = { threadId: crypto.randomUUID(), runId: crypto.randomUUID(), messages: [{ id: "m1", role: "user", content: "見たい" }], tools: [], state: {}, context: [], forwardedProps: {} };
    const r = await probe("secure", "probe-customer-app", "call-sales-agent", { path: "/agui", body: input, token: b, dpopKey: alice.dpopKey });
    expect(r.status).toBe(401);
  });

  it.each<[Ns, number]>([
    ["secure", 401],
    ["vulnerable", 200],
  ])("%s: 盗んだ C を、結ばれた鍵と違う鍵の持ち主（別のノードの複製）から出すと、G26 で止まる（vulnerable は G26 を外す）", async (ns, status) => {
    const alice = await customer(ns, "alice");
    const c = (await exchangeAs(ns, "probe-mcp-1", await atMcp(alice), "insurer-backend")).body.access_token;
    if (ns === "vulnerable") await setDefenses({ "G26@insurer-backend": "off" });
    const r = await probe(ns, "probe-mcp-2", "call-service", { service: "insurer-backend", path: "/contracts", method: "GET", token: c });
    expect(r.status).toBe(status);
  });

  it("secure: ログインサーバーにも、防御を外す受け口がない（D-24）", async () => {
    const r: Json = await probe("secure", "probe-intruder", "admin", { service: "insurer-login", port: 9091, path: "/defenses", method: "GET" });
    expect(r.status).toBeUndefined();
  });

  it("secure: 防御を外す受け口がない（D-24）", async () => {
    const r: Json = await probe("secure", "probe-intruder", "admin", { service: "insurer-backend", port: 9090, path: "/defenses" }).catch((e) => ({ error: String(e) }));
    expect(r.status).toBeUndefined();
  });

  it("secure: 証明書のない接続と、もう一方の名前空間への接続は、つながらない", async () => {
    const alice = await customer("secure", "alice");
    const noCert = await probe("secure", "probe-mcp-1", "call-service", { service: "insurer-backend", path: "/applications", token: alice.token, body: {}, clientCert: false });
    expect(noCert.status).toBeUndefined();
    expect((await probe("secure", "probe-mcp-1", "reach-other-namespace", { namespace: "vulnerable", service: "insurer-backend" })).connected).toBe(false);
  });

  it("secure: トークンを URL に入れない（G24）。基本の流れのどの呼び出しのパスにも、トークンが現れない", async () => {
    await records("secure");
    const logs = await Promise.all(
      ["sales-agent", "insurer-mcp", "insurer-backend"].map(async (d) => {
        const { execFile } = await import("node:child_process");
        return new Promise<string>((resolve) =>
          execFile("kubectl", ["-n", "secure", "logs", `deploy/${d}`, "-c", "envoy", "--tail=2000"], { maxBuffer: 64 << 20 }, (_e, out) => resolve(out)),
        );
      }),
    );
    const paths = logs.join("\n").split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l).path as string);
    expect(paths.length).toBeGreaterThan(3);
    expect(paths.filter((p) => /eyJ[\w-]+\.eyJ/.test(p))).toEqual([]);
  });
});
