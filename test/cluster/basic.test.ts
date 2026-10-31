// 基本の流れ: 相談 → 署名つきの提示 → 意向確認と申込みへの署名 → 回付 → 記録 → 直送 → 照合（architecture の 3 章）。
import { describe, expect, it } from "vitest";
import { reconcile } from "../../packages/customer-app/src/reconcile.ts";
import { Customer, records, setDefenses, type Ns, type Offer } from "./world.ts";

describe.each<Ns>(["secure", "vulnerable"])("基本の流れ（%s）", (ns) => {
  it("顧客が選んで署名した案が、取り次いだ窓口と一緒に記録され、顧客へ直接届く", async () => {
    if (ns === "vulnerable") await setDefenses({});
    const alice = await new Customer(ns, "alice").setup();
    const chat = await alice.salesAgent("/chat", { message: "老後の生活費に備えたい" });
    expect(chat.status, JSON.stringify(chat)).toBe(200);
    if (ns === "vulnerable") expect(chat.body.engine).toBe("scripted");
    const offer = chat.body.offer as Offer;
    expect(offer.offerSet.customer).toBe("alice");

    const submission = alice.prepare(offer, "fixed-60");
    const submitted = await alice.salesAgent("/submit", { ...submission, offerSet: offer.offerSet });
    expect(submitted.status, JSON.stringify(submitted)).toBe(200);

    const record = (await records(ns)).contracts.find((c) => c.contract.nonce === offer.nonce);
    expect(record?.by).toEqual(["insurer-mcp", "sales-agent"]);
    expect(record?.contract.plan.id).toBe("fixed-60");
    const result = reconcile([submission.application as never], (await alice.notices()) as never);
    expect(result.filter((r) => r.nonce === offer.nonce).map((r) => r.status)).toEqual(["match"]);
  });
});
