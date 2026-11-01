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
    expect(await alice.error()).toBeNull();

    const nonce = await alice.nonce;
    const record = (await records(ns)).contracts.find((c) => c.contract.nonce === nonce);
    expect(record?.by).toEqual(["insurer-mcp", "sales-agent"]);
    expect(record?.contract.plan.id).toBe("fixed-60");
    // 会話の最後には、今回の申込みの行だけが出る
    expect(await alice.reconcile()).toBe("match");
    expect(await alice.page.locator("[data-testid^=reconcile-]").count()).toBe(1);
    // 「受信箱と契約」の画面にも、今回の契約が一致として出る
    expect((await alice.inbox()).status).toBe("match");
  });
});

describe("認可サーバーに登録が残っていないとき", () => {
  it("secure: ログインの後に、端末の登録が見つからないことに気付き、登録し直しに案内する", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    // 認可サーバーが再起動して登録を忘れた状態を、端末に存在しない passkey の識別子を置いて作る
    await alice.page.evaluate(() => {
      const key = "device:alice";
      const device = JSON.parse(localStorage.getItem(key)!);
      localStorage.setItem(key, JSON.stringify({ ...device, credentialId: "AAAAAAAAAAAAAAAAAAAAAA" }));
    });
    await alice.page.reload();
    await alice.page.getByTestId("register-note").waitFor();
    expect(await alice.page.getByTestId("register-passkey").isVisible()).toBe(true);
    // 登録し直すと、相談に戻れる
    await alice.registerPasskey();
    expect(await alice.page.getByTestId("register-note").isVisible()).toBe(false);
  });
});
