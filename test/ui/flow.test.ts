// 画面の基本の流れ: ログイン → passkey と受信箱の登録 → 相談 → 署名を確かめた案 → 確認 → 署名 → 提出 → 直送の照合（architecture の 3 章）。
// ブラウザは入口を通り、トークンと DPoP の鍵と passkey は、ブラウザの中にある（D-18）。secure では、本物の Claude が案を示す。
import { afterEach, describe, expect, it } from "vitest";
import { records, setDefenses, type Ns } from "../cluster/world.ts";
import { BrowserCustomer, PLANS } from "./browser.ts";

let alice: BrowserCustomer | undefined;
afterEach(async () => {
  await alice?.close();
  alice = undefined;
});

describe.each<Ns>(["secure", "vulnerable"])("画面の基本の流れ（%s）", (ns) => {
  it("顧客が画面で選んで署名した案が記録され、直接届いた契約内容と照合で一致する", async () => {
    if (ns === "vulnerable") await setDefenses({});
    alice = await new BrowserCustomer(ns, "alice").ready();
    await alice.chat();
    expect(await alice.error()).toBeNull();
    expect(await alice.planIds()).toContain("fixed-60");
    expect(await alice.offerWarning()).toBeNull();

    await alice.choose("fixed-60");
    expect(await alice.approveIfShows(PLANS["fixed-60"]!)).toBe(true);
    expect(await alice.submitResult()).toContain("申し込みました");

    const record = (await records(ns)).contracts.find((c) => c.contract.nonce === alice!.nonce);
    expect(record?.by).toEqual(["insurer-mcp", "sales-agent"]);
    expect(record?.contract.plan.id).toBe("fixed-60");
    expect(await alice.reconcile()).toBe("match");
  });
});
