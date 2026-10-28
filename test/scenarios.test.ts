// シナリオ: 悪い実装では攻撃が通り、良い実装では弾かれる。
// 台本役の「営業員」は、プロンプトインジェクションで乗っ取られた AI を模す(渡された値を好きに書き換える)。
import { CompactSign, SignJWT, decodeProtectedHeader, generateKeyPair, importJWK } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  agentKey, canonical, challengeOf, offerSetId, reconcile, signOfferSet, urls, verifyOfferSetRemote,
  type Contract, type InsuranceTerms, type Notice, type OfferSet, type Plan,
} from "@gekko/shared";
import { deriveContract } from "../packages/insurer-backend/src/app.js";
import {
  Customer, TERMS, connectMcp, exchange, payloadOf, resetWorld, revokeClient, salesConfig, setBackend, setMcp, startWorld,
  type OfferResult,
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

// 顧客が営業員の窓口に来て、替えた票で MCP につながるまで
async function atMcp(who: Customer = alice, terms: InsuranceTerms[] = TERMS) {
  const ticket = await who.salesTicket(terms);
  const routed = (await exchange("sales-agent", ticket, "insurer-mcp")).access_token!;
  return { ticket, routed, mcp: await connectMcp(routed) };
}
type Mcp = Awaited<ReturnType<typeof atMcp>>["mcp"];
const getOffer = async (mcp: Mcp) => (await mcp.call<OfferResult>("get_offers")).body;
const apply = (mcp: Mcp, sub: object, extras?: Record<string, unknown>) =>
  mcp.call("submit_application", { ...sub, ...(extras ? { extras } : {}) });
const backendGet = (path: string, token: string) => fetch(`${urls.insurerBackend}${path}`, { headers: { authorization: `Bearer ${token}` } });
const backendState = async () =>
  (await (await fetch(`${urls.insurerBackend}/debug/state`)).json()) as {
    contracts: { contract: Contract; by: string[] }[]; outbox: { to: string; notice: Notice; delivered: boolean }[];
  };
const noticesOf = async (user: string) => (await (await fetch(`${urls.customerApp}/api/notices?customer=${user}`)).json()) as Notice[];
const planOf = (offer: OfferResult, id: string) => offer.offerSet.plans.find((p) => p.id === id)!;

describe("基本の流れ(good)", () => {
  it("営業員が案を示し、顧客が選んで署名し、事務センターが記録し、顧客へ直接通知する", async () => {
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
    expect(st.contracts[0]!.by).toEqual(["insurer-mcp", "sales-agent"]);

    // 営業員を通らない通知と、顧客の手元の写しが一致する
    const r = reconcile([sub.application], await noticesOf("alice"));
    expect(r).toEqual([{ nonce: sub.application.nonce, status: "match", diffs: [] }]);
  });
});

describe("1. 宛先(aud)を見ない", () => {
  it("bad: 営業員宛ての票で、事務センターの契約が照会できてしまう", async () => {
    setBackend({ ticket: "no-aud" });
    expect((await backendGet("/contracts", await alice.salesTicket())).status).toBe(200);
  });
  it("good: aud が違うので弾かれる", async () => {
    expect((await backendGet("/contracts", await alice.salesTicket())).status).toBe(401);
  });
});

describe("2. トークンの素通し", () => {
  it("bad: MCP が受け取った票をそのまま事務センターへ流し、事務センターも宛先を見ない", async () => {
    setMcp({ backendAuth: "passthrough" });
    setBackend({ ticket: "no-aud" });
    const { mcp } = await atMcp();
    expect((await mcp.call("list_contracts")).isError).toBe(false);
  });
  it("good(事務センターだけ丁寧): 流用された票は宛先が違うので弾かれる", async () => {
    setMcp({ backendAuth: "passthrough" });
    const { mcp } = await atMcp();
    expect((await mcp.call("list_contracts")).isError).toBe(true);
  });
  it("bad: MCP も事務センターも宛先を見ず票を流すと、営業員宛ての票が奥まで通る", async () => {
    setMcp({ incoming: "no-aud", backendAuth: "passthrough" });
    setBackend({ ticket: "no-aud" });
    const { ticket } = await atMcp();
    const mcp = await connectMcp(ticket);
    expect((await mcp.call("list_contracts")).isError).toBe(false);
  });
  it("good(MCP だけ悪い): 宛先の違う票は、認可サーバーが替えてくれないので奥へ進めない", async () => {
    setMcp({ incoming: "no-aud" });
    const { ticket } = await atMcp();
    const mcp = await connectMcp(ticket);
    const r = await mcp.call("list_contracts");
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("認可サーバーが票を出しませんでした");
  });
  it("good: MCP が宛先を見るので、営業員宛ての票では入れない", async () => {
    const ticket = await alice.salesTicket();
    await expect(connectMcp(ticket)).rejects.toThrow();
  });
});

describe("3. 本人が消える(MCP 自身の資格で事務センターを呼ぶ)", () => {
  const attack = async () => {
    const { mcp } = await atMcp(alice);
    // 乗っ取られた営業員が「bob の契約を見せて」と頼む
    return mcp.call<{ contracts: Contract[] }>("list_contracts", { on_behalf_of: "bob" });
  };
  const bobHasContract = async () => {
    const { mcp } = await atMcp(bob);
    await apply(mcp, bob.prepare(await getOffer(mcp), "med-light"));
  };
  it("bad: 本人が消え、引数の言葉だけで bob の契約が見えてしまう", async () => {
    await bobHasContract();
    setMcp({ backendAuth: "client-credentials" });
    setBackend({ trustFromUser: true });
    const r = await attack();
    expect(r.isError).toBe(false);
    expect(r.body.contracts).toHaveLength(1);
  });
  it("good(MCP だけ悪い): 事務センターが利用者本人の票でないと断る", async () => {
    await bobHasContract();
    setMcp({ backendAuth: "client-credentials" });
    const r = await attack();
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("利用者本人");
  });
  it("good: 替えた票なら sub は alice のまま、act に経由した窓口が残る", async () => {
    const { routed } = await atMcp();
    const p = payloadOf(routed);
    expect(p.sub).toBe("alice");
    expect(p.act).toEqual({ sub: "sales-agent" });
  });
});

describe("4. 署名を見ない / alg=none", () => {
  const forged = async () => {
    const { privateKey } = await generateKeyPair("ES256");
    return new SignJWT({ scope: "consult apply" }).setProtectedHeader({ alg: "ES256", typ: "at+jwt" })
      .setIssuer("insurer-auth").setSubject("alice").setAudience("insurer-backend").setIssuedAt().setExpirationTime("10m").sign(privateKey);
  };
  const algNone = () => {
    const b = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    return `${b({ alg: "none", typ: "at+jwt" })}.${b({ iss: "insurer-auth", sub: "alice", aud: "insurer-backend", iat: 1, exp: 4102444800 })}.`;
  };
  it("bad: 偽造した署名も alg=none も通る", async () => {
    setBackend({ ticket: "no-signature" });
    expect((await backendGet("/contracts", await forged())).status).toBe(200);
    expect((await backendGet("/contracts", algNone())).status).toBe(200);
  });
  it("good: どちらも弾かれる", async () => {
    expect((await backendGet("/contracts", await forged())).status).toBe(401);
    expect((await backendGet("/contracts", algNone())).status).toBe(401);
  });
});

describe("5. 期限を見ない", () => {
  const stale = async () => {
    const { routed } = await atMcp();
    const backendTicket = (await exchange("insurer-mcp", routed, "insurer-backend")).access_token!;
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 11 * 60_000 }); // 票の10分を過ぎる
    return backendTicket;
  };
  it("bad: 期限切れの票が通る", async () => {
    setBackend({ ticket: "no-exp" });
    expect((await backendGet("/contracts", await stale())).status).toBe(200);
  });
  it("good: 期限切れは弾かれる", async () => {
    expect((await backendGet("/contracts", await stale())).status).toBe(401);
  });
});

describe("6. 別の用途の票(ID トークン)を、アクセス用の票として受け付ける", () => {
  it("bad(発行が雑 + typ を見ない): ID トークンで事務センターに入れる", async () => {
    process.env.INSURER_MODE_AUTH = "bad"; // ID トークンの aud に API の識別子まで入る
    setBackend({ ticket: "no-typ" });
    expect((await backendGet("/contracts", (await alice.tokens()).id_token)).status).toBe(200);
  });
  it("good(typ を見る): 発行が雑でも、種類が違うので弾かれる", async () => {
    process.env.INSURER_MODE_AUTH = "bad";
    expect((await backendGet("/contracts", (await alice.tokens()).id_token)).status).toBe(401);
  });
  it("good(発行が丁寧): typ を見なくても、aud が違うので弾かれる", async () => {
    setBackend({ ticket: "no-typ" });
    expect((await backendGet("/contracts", (await alice.tokens()).id_token)).status).toBe(401);
  });
});

describe("7. 申込みの書き換え(署名のあとで AI が案を変える)", () => {
  // alice が「医療 ライト」に署名 → 乗っ取られた営業員が、取決めの範囲で最も保険料が高い案に書き換えて提出する
  const viaAgent = async () => {
    salesConfig.tamper = true;
    const ticket = await alice.salesTicket();
    const auth = { authorization: `Bearer ${ticket}`, "content-type": "application/json" };
    const chat = (await (await fetch(`${urls.salesAgent}/chat`, { method: "POST", headers: auth, body: JSON.stringify({ message: "案を見たい" }) })).json()) as { offer: OfferResult };
    const sub = alice.prepare(chat.offer, "med-light");
    return fetch(`${urls.salesAgent}/submit`, { method: "POST", headers: auth, body: JSON.stringify({ ...sub, offerSet: chat.offer.offerSet }) });
  };
  const recordedPlan = async () => (await backendState()).contracts[0]?.contract.plan.id;
  it("bad(署名と連鎖を見ない): 書き換えが通る", async () => {
    setBackend({ seal: "none", chain: "none" });
    expect((await viaAgent()).status).toBe(200);
    expect(await recordedPlan()).toBe("life-1000");
  });
  it("不十分(mTLS だけ): 通信相手は信頼できる MCP なので、書き換えも通る", async () => {
    setBackend({ seal: "mtls-only", chain: "none" });
    expect((await viaAgent()).status).toBe(200);
    expect(await recordedPlan()).toBe("life-1000");
  });
  it("不十分(AI 自身が署名): 書き換えた張本人が署名するので通る", async () => {
    setBackend({ seal: "agent-signed", chain: "none" });
    const { mcp } = await atMcp();
    const offer = await getOffer(mcp);
    const sub = alice.prepare(offer, "med-light");
    const tampered = { ...sub.application, plan: planOf(offer, "life-1000") };
    const jws = await new CompactSign(new TextEncoder().encode(canonical(tampered)))
      .setProtectedHeader({ alg: "ES256" }).sign(await importJWK(agentKey.priv, "ES256"));
    expect((await apply(mcp, { ...sub, application: tampered, assertion: jws })).isError).toBe(false);
    expect(await recordedPlan()).toBe("life-1000");
  });
  it("good(顧客の署名と内容を照合): 申込みがサイン時と違うので弾かれる", async () => {
    const r = await viaAgent();
    expect(r.status).toBe(403);
    expect(JSON.stringify(await r.json())).toContain("申込みの署名の照合");
    expect((await backendState()).contracts).toHaveLength(0);
  });
  it("good(署名は見ないが、連鎖は見る): 意向確認と食い違うので、2段目が1段目を支える", async () => {
    setBackend({ seal: "none" });
    const r = await viaAgent();
    expect(r.status).toBe(403);
    expect(JSON.stringify(await r.json())).toContain("意向確認");
  });
});

describe("8. 提示にない案で申し込む", () => {
  const gold: Plan = { id: "med-gold", name: "医療 ゴールド", kind: "medical", benefit: 100_000, monthly: 100 };
  // 営業員が、本物の提示から nonce だけ取り、案を足した偽の提示を顧客に見せる。顧客のアプリが署名を確かめなければ、顧客は偽の案に署名する。
  const forge = async () => {
    const { mcp } = await atMcp();
    const offer = await getOffer(mcp);
    const set: OfferSet = { customer: "alice", plans: [...offer.offerSet.plans, gold] };
    return { mcp, offer, set, forged: { ...offer, offerSet: set, offerSetId: offerSetId(set) } as OfferResult };
  };
  it("bad: 保険会社の署名のない提示でも、偽の案で契約が記録される", async () => {
    setBackend({ offers: "none" });
    const { mcp, forged, set, offer } = await forge();
    const key = (await generateKeyPair("ES256")).privateKey;
    const sub = alice.prepare({ ...forged, offerJws: await signOfferSet(key, "x", set, offer.nonce) }, "med-gold");
    expect((await apply(mcp, sub)).isError).toBe(false);
    expect((await backendState()).contracts[0]!.contract.plan.name).toBe("医療 ゴールド");
  });
  it("good: 提示の署名が保険会社のものでなければ弾かれる", async () => {
    const { mcp, forged, set, offer } = await forge();
    const key = (await generateKeyPair("ES256")).privateKey;
    const r = await apply(mcp, alice.prepare({ ...forged, offerJws: await signOfferSet(key, "x", set, offer.nonce) }, "med-gold"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("提示の署名");
  });
  it("good: 本物の提示を添えても、その提示にない案なら弾かれる", async () => {
    const { mcp, forged, offer } = await forge();
    // 提示の識別子と nonce は本物のまま、案だけを差し替える
    const r = await apply(mcp, alice.prepare({ ...forged, offerSetId: offer.offerSetId }, "med-gold"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("案が提示に含まれる");
  });
});

describe("9. 意向確認と申込みの間で内容をすり替える", () => {
  // 顧客は「医療 ライト」の意向確認に署名したが、申込みは「死亡 1,000万円」に署名してしまった。
  const swapped = async () => {
    const { mcp } = await atMcp();
    const offer = await getOffer(mcp);
    const sub = alice.prepare(offer, "med-light");
    const application = { ...sub.application, plan: planOf(offer, "life-1000") };
    return { mcp, sub, swapped: { ...sub, application, assertion: alice.sign(application) } };
  };
  it("bad(連鎖を見ない): 意向と違う申込みが通る", async () => {
    setBackend({ chain: "none" });
    const { mcp, swapped: s } = await swapped();
    expect((await apply(mcp, s)).isError).toBe(false);
    expect((await backendState()).contracts[0]!.contract.plan.id).toBe("life-1000");
  });
  it("good: 意向確認と申込みがつながらないので弾かれる", async () => {
    const { mcp, swapped: s } = await swapped();
    const r = await apply(mcp, s);
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("意向確認と申込みが対応");
  });
  it("good: 意向確認の署名がない申込みは弾かれる", async () => {
    const { mcp, sub } = await swapped();
    const r = await apply(mcp, { ...sub, intentAssertion: undefined });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("意向確認の署名");
  });
});

describe("10. 取決め(RAR)の範囲外", () => {
  it("bad: 給付額の上限を超える案でも、顧客が署名していれば通る", async () => {
    setBackend({ range: "none" });
    const { mcp } = await atMcp();
    const offer = await getOffer(mcp);
    expect((await apply(mcp, alice.prepare(offer, "life-3000"))).isError).toBe(false);
  });
  it("good: 給付額の上限(1,000万円)を超えるので弾かれる", async () => {
    const { mcp } = await atMcp();
    const r = await apply(mcp, alice.prepare(await getOffer(mcp), "life-3000"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("給付額の上限");
  });
  it("good: 取決めにない保険の種類は弾かれる", async () => {
    const { mcp } = await atMcp(alice, MEDICAL_ONLY);
    const r = await apply(mcp, alice.prepare(await getOffer(mcp), "life-1000"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("扱える保険の種類");
  });
  it("bad(署名を見ない)でも、取決めがあれば範囲外の案は止まる(被害の範囲が限られる)", async () => {
    setBackend({ seal: "none", chain: "none", offers: "none" });
    const { mcp } = await atMcp(alice, MEDICAL_ONLY);
    const sub = alice.prepare(await getOffer(mcp), "med-light");
    const offer = await getOffer(mcp);
    const r = await apply(mcp, { ...sub, application: { ...sub.application, plan: planOf(offer, "life-3000") } });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("扱える保険の種類");
  });
});

describe("11. 登録が外れた営業員(AI)の申込み", () => {
  // 票をもらい、案も受け取ったあとで、営業員(AI)の登録が外れる。
  const afterRevoked = async () => {
    const { mcp } = await atMcp();
    const sub = alice.prepare(await getOffer(mcp), "med-light");
    await revokeClient("sales-agent");
    return { mcp, sub };
  };
  it("bad(登録の有効性を見ない): 出済みの票が使い続けられ、申込みが通る", async () => {
    setBackend({ registration: "none" });
    const { mcp, sub } = await afterRevoked();
    expect((await apply(mcp, sub)).isError).toBe(false);
  });
  it("good: 問い合わせで無効と分かり、弾かれる", async () => {
    const { mcp, sub } = await afterRevoked();
    const r = await apply(mcp, sub);
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("登録が有効");
  });
  it("登録が外れた営業員(AI)には、新しい票も出さない", async () => {
    const ticket = await alice.salesTicket();
    await revokeClient("sales-agent");
    expect((await exchange("sales-agent", ticket, "insurer-mcp")).access_token).toBeUndefined();
  });
  it("票の失効(RFC 7009)と有効性の問い合わせ(RFC 7662)", async () => {
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

describe("12. 署名済みの申込みを二度出す", () => {
  it("bad(nonce を見ない): 二度目も記録される", async () => {
    setBackend({ nonce: "none" });
    const { mcp } = await atMcp();
    const sub = alice.prepare(await getOffer(mcp), "med-light");
    expect((await apply(mcp, sub)).isError).toBe(false);
    expect((await apply(mcp, sub)).isError).toBe(false);
    expect((await backendState()).contracts).toHaveLength(2);
  });
  it("good: 二度目は弾かれる", async () => {
    const { mcp } = await atMcp();
    const sub = alice.prepare(await getOffer(mcp), "med-light");
    expect((await apply(mcp, sub)).isError).toBe(false);
    const again = await apply(mcp, sub);
    expect(again.isError).toBe(true);
    expect((await backendState()).contracts).toHaveLength(1);
  });
});

describe("13. 被保険者の同意のない申込み", () => {
  const forBob = async () => {
    const { mcp } = await atMcp();
    return { mcp, offer: await getOffer(mcp) };
  };
  it("good: 被保険者(bob)自身の署名があれば通る", async () => {
    const { mcp, offer } = await forBob();
    const r = await apply(mcp, alice.prepare(offer, "med-light", { insured: bob }));
    expect(r.isError).toBe(false);
    expect((await backendState()).contracts[0]!.contract.insured).toBe("bob");
  });
  it("bad(被保険者の署名を見ない): bob の同意なしに、bob を被保険者にできる", async () => {
    setBackend({ insured: "none" });
    const { mcp, offer } = await forBob();
    const sub = alice.prepare(offer, "med-light", { insured: bob });
    expect((await apply(mcp, { ...sub, insuredAssertion: undefined })).isError).toBe(false);
  });
  it("good: 被保険者の署名がなければ弾かれる", async () => {
    const { mcp, offer } = await forBob();
    const sub = alice.prepare(offer, "med-light", { insured: bob });
    const r = await apply(mcp, { ...sub, insuredAssertion: undefined });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("被保険者の署名");
  });
  it("good: bob になりすまして alice 自身が署名しても、bob のパスキーではないので弾かれる", async () => {
    const { mcp, offer } = await forBob();
    const sub = alice.prepare(offer, "med-light", { insured: bob });
    const r = await apply(mcp, { ...sub, insuredAssertion: alice.sign(sub.application) });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("被保険者の署名");
  });
});

describe("14. 本人確認が済んだことを、営業員の申告で済ませる", () => {
  it("票には、確認の済んだ顧客だけに確認済みの属性が付く", async () => {
    expect(payloadOf(await alice.salesTicket()).verified_claims.verification.method).toBeTruthy();
    expect(payloadOf(await mallory.salesTicket()).verified_claims).toBeUndefined();
  });
  it("good: 本人確認が済んでいない顧客(mallory)の申込みは弾かれる", async () => {
    const { mcp } = await atMcp(mallory);
    const r = await apply(mcp, mallory.prepare(await getOffer(mcp), "med-light"));
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("本人確認");
  });
  it("bad(営業員の申告を信じる): alice の確認済みの属性を付け足すと、mallory の申込みが通る", async () => {
    setBackend({ identity: "agent-claim" });
    const claims = payloadOf(await alice.salesTicket()).verified_claims;
    const { mcp } = await atMcp(mallory);
    const sub = mallory.prepare(await getOffer(mcp), "med-light");
    expect((await apply(mcp, sub)).isError).toBe(true); // 申告がなければ止まる
    expect((await apply(mcp, sub, { verified_claims: claims })).isError).toBe(false);
  });
  it("good: 申告を付け足しても、票の属性しか見ないので弾かれる", async () => {
    const claims = payloadOf(await alice.salesTicket()).verified_claims;
    const { mcp } = await atMcp(mallory);
    const r = await apply(mcp, mallory.prepare(await getOffer(mcp), "med-light"), { verified_claims: claims });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r.body)).toContain("本人確認が済んでいる");
  });
});

describe("15. 正しく検証できない票を発行する(認可サーバーが悪い)", () => {
  it("bad: 全窓口が宛先の万能票は、丁寧な事務センターでも通してしまう", async () => {
    process.env.INSURER_MODE_AUTH = "bad";
    expect((await backendGet("/contracts", await alice.salesTicket())).status).toBe(200);
  });
  it("bad: 有効期間が長い", async () => {
    process.env.INSURER_MODE_AUTH = "bad";
    const p = payloadOf(await alice.salesTicket());
    expect(p.exp - p.iat).toBe(24 * 3600);
  });
  it("bad: 替えた票から act が消え、誰を経由したか分からなくなる", async () => {
    process.env.INSURER_MODE_AUTH = "bad";
    const { routed } = await atMcp();
    expect(payloadOf(routed).act).toBeUndefined();
  });
  const wide = JSON.stringify([{ type: "insurance_application", kinds: ["medical", "death"], maxBenefit: 100_000_000 }]);
  it("bad: 替えるときに取決めを広げられる", async () => {
    process.env.INSURER_MODE_AUTH = "bad";
    const ticket = await alice.salesTicket();
    const routed = (await exchange("sales-agent", ticket, "insurer-mcp", { authorization_details: wide })).access_token!;
    expect(payloadOf(routed).authorization_details[0].maxBenefit).toBe(100_000_000);
  });
  it("good: 万能票は出さず、取決めは広げられず、期間は短く、act が残る", async () => {
    const ticket = await alice.salesTicket();
    expect((await backendGet("/contracts", ticket)).status).toBe(401);
    const routed = (await exchange("sales-agent", ticket, "insurer-mcp", { authorization_details: wide })).access_token!;
    const p = payloadOf(routed);
    expect(p.authorization_details[0]).toMatchObject({ maxBenefit: 10_000_000 });
    expect(p.act).toEqual({ sub: "sales-agent" });
    expect(p.exp - p.iat).toBe(600);
    expect(decodeProtectedHeader(routed).typ).toBe("at+jwt");
  });
});

describe("16. 契約の記録を、署名のない入力から作る", () => {
  const withEntry = async () => {
    const { mcp } = await atMcp();
    const offer = await getOffer(mcp);
    const sub = alice.prepare(offer, "med-light");
    return { mcp, sub, r: await apply(mcp, sub, { contractEntry: { plan: planOf(offer, "life-3000") } }) };
  };
  it("bad(人の入力を信じる): 署名と違う契約が記録される。顧客の自動照合が、不一致に気づく", async () => {
    setBackend({ ingest: "manual" });
    const { sub, r } = await withEntry();
    expect(r.isError).toBe(false);
    expect((await backendState()).contracts[0]!.contract.plan.id).toBe("life-3000");
    const rec = reconcile([sub.application], await noticesOf("alice"));
    expect(rec[0]).toMatchObject({ status: "mismatch" });
    expect(rec[0]!.diffs).toContain("案");
  });
  it("good: 署名済みの申込みから導出するので、入力欄を付け足しても効かない", async () => {
    const { sub, r } = await withEntry();
    expect(r.isError).toBe(false);
    const recorded = (await backendState()).contracts[0]!.contract;
    expect(recorded).toEqual(deriveContract(sub.application));
    expect(recorded.contractId).toBe(`C-${challengeOf(sub.application).slice(0, 12)}`);
  });
});

describe("17. 直送の通知先を、営業員が書いた連絡先にする", () => {
  const apply1 = async (extras?: Record<string, unknown>) => {
    const { mcp } = await atMcp();
    const sub = alice.prepare(await getOffer(mcp), "med-light");
    await apply(mcp, sub, extras);
    return sub;
  };
  it("good: 登録済みの連絡先へ届き、手元の写しと一致する", async () => {
    const sub = await apply1({ contact: "http://localhost:9/notices" });
    const st = await backendState();
    expect(st.outbox[0]).toMatchObject({ to: `${urls.customerApp}/notices?customer=alice`, delivered: true });
    expect(reconcile([sub.application], await noticesOf("alice"))[0]!.status).toBe("match");
  });
  it("bad(申込みの連絡先に送る): 通知が顧客に届かない。自動照合が、届かないことに気づく", async () => {
    setBackend({ notify: "from-application" });
    const sub = await apply1({ contact: "http://localhost:9/notices" });
    const st = await backendState();
    expect(st.outbox[0]).toMatchObject({ to: "http://localhost:9/notices", delivered: false });
    expect(await noticesOf("alice")).toHaveLength(0);
    expect(reconcile([sub.application], [])[0]!.status).toBe("missing");
  });
  it("覚えのない通知(申し込んでいない契約)も、自動照合で見つかる", () => {
    const stray: Notice = { customer: "alice", contract: { contractId: "C-x", customer: "alice", insured: "alice", offerSetId: "x", nonce: "n-x", plan: { id: "p", name: "p", kind: "death", benefit: 1, monthly: 1 } } };
    expect(reconcile([], [stray])[0]).toMatchObject({ status: "unexpected" });
  });
});
