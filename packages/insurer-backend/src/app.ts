// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
// 事務センター(保険会社のバックエンド) = 最後の砦。票と申込みを照合してから契約を記録し、顧客へ直接通知する。
import { Hono } from "hono";
import {
  actChain, bearer, canonical, challengeOf, emit, modeOf, offerSetId, signOfferSet, verifyOfferSet, VerifyError,
  type Application, type CheckResult, type Contract, type Intent, type Notice, type OfferSet, type Ticket, type VerifiedClaims, urls,
} from "@gekko/shared";
import { randomUUID } from "node:crypto";
import { catalog, contracts, customers, nonces, offerKey, offerKid, offerJwk, outbox } from "./state.js";
import { config, isGood } from "./config.js";
import { ticketChecklist, verifyTicket } from "./verify/ticket.js";
import { verifyAgentSigned, verifyMtlsOnly, verifyNone, verifyPasskey } from "./verify/seal.js";

const ticketView = (t?: Ticket) =>
  t ? { sub: t.sub, aud: t.aud, act: actChain(t.act), scope: t.scope, exp: t.exp } : undefined;

// 提出された一式。営業員(AI)と MCP を経由して届く。経路の途中で書き換えられうるものとして扱う。
interface Submission {
  offerJws?: string;
  intent: Intent;
  intentAssertion: any;
  application: Application;
  assertion: unknown;
  insuredAssertion?: unknown;
  // 以下は、営業員(AI)が付け足せる欄。良い実装は使わない。
  verified_claims?: VerifiedClaims;
  contact?: string;
  contractEntry?: Partial<Contract>;
}

// 契約の記録は、署名済みの申込みから決まった規則で作る。人も AI も入力し直さない。
export function deriveContract(a: Application): Contract {
  return {
    contractId: `C-${challengeOf(a).slice(0, 12)}`,
    customer: a.customer, insured: a.insured, plan: a.plan, offerSetId: a.offerSetId, nonce: a.nonce,
  };
}

const INTROSPECT_AUTH = "Basic " + Buffer.from("insurer-backend:insurer-backend-secret").toString("base64");

export function createApp() {
  const app = new Hono();
  const actor = "事務センター";
  const mode = () => (isGood() ? "good" : "bad");

  // 票を検証して返す。失敗したら理由つきでイベントを出す。
  async function authenticate(header: string | undefined, action: string) {
    let token: string;
    try { token = bearer(header); } catch (e) {
      await emit({ actor, mode: mode(), action, checks: [{ name: "票が付いている", ok: false, detail: (e as Error).message }], outcome: "rejected" });
      return { error: (e as Error).message };
    }
    try {
      const ticket = await verifyTicket(token, config.ticket);
      return { token, ticket, checks: ticketChecklist(config.ticket).map((c): CheckResult => ({
        name: c.name, ok: true, detail: c.on ? undefined : "⚠ この項目は確認していません" })) };
    } catch (e) {
      const msg = e instanceof VerifyError ? e.message : String(e);
      await emit({ actor, mode: mode(), action, checks: [{ name: "票の検証", ok: false, detail: msg }], outcome: "rejected" });
      return { error: msg };
    }
  }

  // 「誰の契約か」は票の sub から決める。悪い実装は、窓口が言う for_user をそのまま信じる。
  const customerOf = (t: Ticket, forUser?: string) => (config.trustFromUser && forUser ? forUser : t.sub);

  app.get("/offers-jwks.json", (c) => c.json({ keys: [offerJwk] }));

  // 提示。顧客ごとに、案の一式へ保険会社が署名して返す。
  app.post("/offers", async (c) => {
    const a = await authenticate(c.req.header("authorization"), "提示の取得");
    if (!a.ticket) return c.json({ error: a.error }, 401);
    const body = (await c.req.json().catch(() => ({}))) as { for_user?: string };
    const customer = customerOf(a.ticket, body.for_user);
    if (!customers[customer]) {
      await emit({ actor, mode: mode(), action: "提示の取得", ticket: ticketView(a.ticket), checks: [...a.checks, { name: "票の利用者本人が顧客である", ok: false, detail: `sub=${a.ticket.sub} は顧客ではありません` }], outcome: "rejected" });
      return c.json({ error: "利用者本人の票ではありません" }, 403);
    }
    const set: OfferSet = { customer, plans: catalog };
    const nonce = randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    nonces.set(nonce, { customer, expiresAt, used: false });
    const offerJws = await signOfferSet(offerKey.privateKey, offerKid, set, nonce);
    await emit({ actor, mode: mode(), action: "提示の取得", ticket: ticketView(a.ticket), checks: a.checks, outcome: "ok" });
    return c.json({ offerJws, offerSet: set, offerSetId: offerSetId(set), nonce, expiresAt });
  });

  // 契約の照会
  app.get("/contracts", async (c) => {
    const a = await authenticate(c.req.header("authorization"), "契約の照会");
    if (!a.ticket) return c.json({ error: a.error }, 401);
    const customer = customerOf(a.ticket, c.req.query("for_user"));
    if (!customers[customer]) return c.json({ error: "利用者本人の票ではありません" }, 403);
    return c.json({ contracts: contracts.filter((r) => r.contract.customer === customer).map((r) => r.contract) });
  });

  // 申込みの受付
  app.post("/applications", async (c) => {
    const action = "申込みの受付";
    const a = await authenticate(c.req.header("authorization"), action);
    if (!a.ticket) return c.json({ error: a.error }, 401);
    const ticket = a.ticket;
    const body = (await c.req.json()) as Submission;
    const { application, intent } = body;
    const checks: CheckResult[] = [...a.checks];
    const reject = async (name: string, detail: string, status: 403 | 409 = 403) => {
      checks.push({ name, ok: false, detail });
      await emit({ actor, mode: mode(), action, ticket: ticketView(ticket), checks, outcome: "rejected" });
      return c.json({ error: `${name}: ${detail}` }, status);
    };
    const pass = (name: string, detail?: string) => checks.push({ name, ok: true, detail });
    const skipped = (name: string) => checks.push({ name, ok: true, detail: "⚠ この項目は確認していません" });

    // 窓口自身の票(sub が顧客ではない)を内部の信頼できる呼び出しとみなす悪い実装がある。
    const serviceTicket = config.trustFromUser && !customers[ticket.sub];
    const customer = serviceTicket ? application.customer : ticket.sub;
    if (!customers[customer]) return reject("票の利用者本人が顧客である", `sub=${ticket.sub} は顧客ではありません`);
    if (application.customer !== customer) return reject("申込みの契約者が票の本人", `${application.customer} は ${customer} ではありません`);

    // 1. 票を取り次いだ営業員(AI)が、今も登録されているか
    if (config.registration === "introspect") {
      const r = await fetch(`${urls.insurerAuth}/introspect`, {
        method: "POST", headers: { authorization: INTROSPECT_AUTH, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: a.token }),
      });
      if (!((await r.json()) as { active?: boolean }).active) return reject("取り次いだ営業員(AI)の登録が有効", "票が無効か、登録が外れています");
      pass("取り次いだ営業員(AI)の登録が有効");
    } else skipped("取り次いだ営業員(AI)の登録が有効");

    // 2. 本人確認が済んでいるか。確認済みの属性は、票から取る。
    const claims = config.identity === "token" ? ticket.verified_claims : (body.verified_claims ?? ticket.verified_claims);
    if (!claims?.verification?.method) return reject("本人確認が済んでいる", "確認済みの属性がありません");
    if (config.identity === "token") pass("本人確認が済んでいる(票の属性)", `${claims.verification.method}`);
    else checks.push({ name: "本人確認が済んでいる", ok: true, detail: "⚠ 営業員の申告を信じています" });

    // 3. 案が、保険会社の署名つきの提示に含まれるか
    if (config.offers === "verify") {
      try {
        const offer = await verifyOfferSet(String(body.offerJws), offerKey.publicKey);
        if (offer.customer !== customer) return reject("提示は本人宛て", `${offer.customer} 宛ての提示です`);
        if (offer.offerSetId !== application.offerSetId || offer.nonce !== application.nonce) return reject("申込みが提示と対応", "提示集合の識別子か nonce が違います");
        if (!offer.plans.some((p) => canonical(p) === canonical(application.plan))) return reject("案が提示に含まれる", "提示にない案です");
      } catch (e) {
        return reject("提示の署名が有効", (e as Error).message);
      }
      pass("案は署名つきの提示に含まれる");
    } else skipped("案は署名つきの提示に含まれる");

    // 4. 申込みの内容が、署名時のままか
    const peer = c.req.header("x-peer");
    const seal = await ({ passkey: verifyPasskey, none: verifyNone, "mtls-only": verifyMtlsOnly, "agent-signed": verifyAgentSigned }[config.seal])
      ({ content: application, assertion: body.assertion, user: customer, peer });
    if (!seal.ok) return reject("申込みの署名の照合", seal.detail);
    if (config.seal === "passkey") pass("契約者のパスキーによる署名(誰が)と、内容の一致(何を)", seal.detail);
    else checks.push({ name: "申込みの署名の照合", ok: true, detail: `⚠ ${seal.detail}` });

    // 5. 被保険者が別人なら、その人の署名
    if (application.insured !== customer) {
      if (config.insured === "required") {
        if (!customers[application.insured]) return reject("被保険者が顧客である", `${application.insured} は顧客ではありません`);
        const r = await verifyPasskey({ content: application, assertion: body.insuredAssertion, user: application.insured });
        if (!r.ok) return reject("被保険者の署名", r.detail);
        pass("被保険者自身の署名");
      } else skipped("被保険者自身の署名");
    }

    // 6. 意向確認と申込みの署名の連鎖
    if (config.chain === "verify") {
      const r = await verifyPasskey({ content: intent, assertion: body.intentAssertion, user: customer });
      if (!r.ok) return reject("意向確認の署名", r.detail);
      const same = intent.customer === customer && intent.offerSetId === application.offerSetId
        && intent.planId === application.plan.id && intent.nonce === application.nonce
        && body.intentAssertion?.response?.signature === application.intentSignature;
      if (!same) return reject("意向確認と申込みが対応", "申込みが、署名した意向確認とつながっていません");
      pass("意向確認の署名と申込みがつながる");
    } else skipped("意向確認の署名と申込みがつながる");

    // 7. 取決め(扱える保険の種類、給付額の上限)との照合
    if (serviceTicket) {
      skipped("取決めとの照合");
    } else {
      if (!ticket.scope?.split(" ").includes("apply")) return reject("取決め(scope)", "apply が許されていません");
      if (config.range === "rar") {
        const terms = ticket.authorization_details?.[0];
        if (!terms) return reject("取決め(RAR)", "取決めがありません");
        if (!terms.kinds.includes(application.plan.kind)) return reject("扱える保険の種類", `${application.plan.kind} は取決めの範囲外です`);
        if (application.plan.benefit > terms.maxBenefit) return reject("給付額の上限以内", `${application.plan.benefit} 円は上限 ${terms.maxBenefit} 円を超えています`);
        pass("取決めの範囲内");
      } else skipped("取決めの範囲内");
    }

    // 8. 一度しか受け付けない
    const n = nonces.get(application.nonce);
    if (config.nonce === "once") {
      if (!n || n.used || n.customer !== customer || n.expiresAt < Date.now() / 1000 || application.expiresAt < Date.now() / 1000)
        return reject("申込みは未使用で期限内", "使用済み、期限切れ、または発行していない nonce です", 409);
      pass("申込みは未使用で期限内");
    } else skipped("申込みは未使用で期限内");
    if (n) n.used = true;

    // 9. 契約の記録。署名済みの申込みから導出する。悪い実装は、人が入力した内容を信じる。
    const derived = deriveContract(application);
    const contract: Contract = config.ingest === "derive" ? derived : { ...derived, ...body.contractEntry };
    if (config.ingest === "derive") pass("契約の記録は署名済みの申込みから導出");
    else checks.push({ name: "契約の記録", ok: true, detail: "⚠ 入力された内容をそのまま記録しています" });
    const by = actChain(ticket.act);
    contracts.push({ contract, by, at: Date.now(), application, intent, assertion: body.assertion, offerJws: body.offerJws });
    pass("取り次いだ窓口と署名済みの申込みを記録", by.length ? `${by.join(" ← ")}(経由)` : "経路の記録がありません");

    // 10. 顧客へ直接通知する(営業員を通さない)。宛先は登録済みの連絡先。
    const to = config.notify === "registered" ? customers[customer]!.contact : (body.contact ?? customers[customer]!.contact);
    const notice: Notice = { customer, contract };
    const entry = { to, notice, delivered: false };
    outbox.push(entry);
    entry.delivered = await fetch(to, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(notice), signal: AbortSignal.timeout(1500),
    }).then((r) => r.ok).catch(() => false);
    pass("登録済みの連絡先へ直接通知", config.notify === "registered" ? undefined : `⚠ 通知先を申込みから取っています: ${to}`);

    await emit({ actor, mode: mode(), action, ticket: ticketView(ticket), checks, outcome: "ok" });
    return c.json({ ok: true, contract });
  });

  // 教材用の確認窓口(契約と通知)
  app.get("/debug/state", (c) => c.json({ contracts, outbox, config }));
  return app;
}
