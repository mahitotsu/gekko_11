import { describe, expect, it } from "vitest";
import { contentSecurityPolicy, createApp, peerOf } from "../src/app.ts";
import { reconcile } from "../src/reconcile.ts";

const notice = { customer: "alice", contract: { contractId: "C-1", nonce: "n-1" } };
const xfcc = (sa: string) => `Hash=ab;URI=spiffe://gekko11.internal/ns/secure/sa/${sa}`;

describe("画面の CSP（D32）", () => {
  it("スクリプトとスタイルは配信元だけで、つなぐ先を限る", () => {
    Object.assign(process.env, { AGENT_ORIGIN: "http://agent.test", AUTH_ORIGIN: "http://auth.test", ISSUER: "http://login.test/realms/insurer" });
    const policy = contentSecurityPolicy();
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("script-src 'self'");
    expect(policy).not.toContain("unsafe");
    expect(policy).toContain("connect-src 'self' http://agent.test http://auth.test http://login.test");
    expect(policy).toContain("style-src 'self'");
  });
});

describe("直送の受け口", () => {
  it("保険会社のシステムからの通知だけを受ける", async () => {
    const app = createApp();
    const inbox = "Abcdefghijklmnopqrstuv";
    const post = (sa?: string) =>
      app.request(`/notices/${inbox}`, {
        method: "POST",
        headers: { "content-type": "application/json", ...(sa ? { "x-forwarded-client-cert": xfcc(sa) } : {}) },
        body: JSON.stringify(notice),
      });
    expect((await post("sales-agent")).status).toBe(403);
    expect((await post()).status).toBe(403);
    expect((await post("insurer-backend")).status).toBe(204);
    expect(await (await app.request(`/api/inbox/${inbox}`)).json()).toEqual([notice]);
    // 番号を知らなければ、読めない
    expect(await (await app.request("/api/inbox/Zbcdefghijklmnopqrstuv")).json()).toEqual([]);
  });

  it("XFCC から相手の SPIFFE ID を読む", () => {
    expect(peerOf(`By=x;Hash=ab;URI="spiffe://d/ns/n/sa/a"`)).toBe("spiffe://d/ns/n/sa/a");
    expect(peerOf(undefined)).toBeUndefined();
  });
});

describe("照合", () => {
  const plan = { id: "fixed-60", benefit: 600_000, monthly: 20_000 };
  const copy = { customer: "alice", plan, offerSetId: "s", nonce: "n-1" };
  it("一致、食い違い、未着、覚えのない通知を見分ける", () => {
    expect(reconcile([copy], [{ contract: { ...copy } }])[0]?.status).toBe("match");
    const other = { ...copy, plan: { ...plan, id: "life-240", monthly: 120_000 } };
    expect(reconcile([copy], [{ contract: other }])[0]).toMatchObject({ status: "mismatch", diffs: ["案", "保険料"] });
    expect(reconcile([copy], [])[0]?.status).toBe("missing");
    expect(reconcile([], [{ contract: copy }])[0]?.status).toBe("unexpected");
  });
});
