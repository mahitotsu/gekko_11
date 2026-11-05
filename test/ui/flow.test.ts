// 画面の基本の流れ: ログイン → passkey と受信箱の登録 → 相談 → 署名を確かめた案 → 確認 → 署名 → 提出 → 直送の照合（architecture の 3 章）。
// ブラウザは入口を通り、トークンと DPoP の鍵と passkey は、ブラウザの中にある（D-18）。secure では、本物の Claude が案を示す。
import type { Page } from "playwright-core";
import { afterEach, describe, expect, it } from "vitest";
import { publicOrigin, records, setDefenses, type Ns } from "../cluster/world.ts";
import { BrowserAuditor, BrowserCustomer, PLANS } from "./browser.ts";

let alice: BrowserCustomer | undefined;
let auditor: BrowserAuditor | undefined;
afterEach(async () => {
  await alice?.close();
  await auditor?.close();
  alice = undefined;
  auditor = undefined;
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

    // 監査の担当が、監査の画面で、その契約を食い違いなしと見て、会話の記録を読める（D25、D-31）
    auditor = new BrowserAuditor(ns);
    expect(await auditor.open()).toBe(200);
    const audited = await auditor.contract(nonce, (status, rows) => status === "食い違いなし" && rows > 0);
    expect(audited.status).toBe("食い違いなし");
    expect(audited.conversationRows).toBeGreaterThan(0);
    // 詳細の冒頭に、何と何を比べたかが出る
    expect(await auditor.page.getByTestId("comparison").count()).toBeGreaterThan(0);
  });
});

describe("カードで進む申込み（vulnerable の台本）", () => {
  const start = async () => {
    await setDefenses({});
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    return alice.page;
  };
  const send = async (page: Page, text: string) => {
    await page.getByTestId("free-input").fill(text);
    await page.getByTestId("free-send").click();
  };

  it("「その他」の文が意向確認書面に出て、入力欄は許したカードにだけある", async () => {
    const page = await start();
    await send(page, "老後に備えたい");
    await expect.poll(() => page.getByTestId("ask-other-input").isVisible()).toBe(true);
    expect(await page.getByTestId("free-input").count()).toBe(0);
    await page.getByTestId("ask-other-input").fill("10 年だけ受け取りたい");
    await page.getByTestId("ask-other-send").click();
    await page.getByTestId("choose-fixed-60").waitFor();
    // 案のカードに、入力欄はない。段階も進む
    expect(await page.locator("textarea:visible").count()).toBe(0);
    expect(await page.locator("#steps li[aria-current]").getAttribute("data-step")).toBe("offers");
    expect(await page.locator("#steps li.done").getAttribute("data-step")).toBe("consult");
    await page.getByTestId("choose-fixed-60").click();
    await page.getByTestId("sign-intent").waitFor();
    expect(await page.locator("textarea:visible").count()).toBe(0);
    expect(await page.getByTestId("intent-confirm").textContent()).toContain("10 年だけ受け取りたい");
    // 終わったカードは閉じ、答えを 1 行で読める。開けば中身を読める
    const offers = page.getByTestId("offers");
    expect(await offers.getAttribute("open")).toBeNull();
    expect(await offers.locator("summary").textContent()).toContain(PLANS["fixed-60"]!.name);
  });

  it("「null」と答えても止まらない", async () => {
    const page = await start();
    await send(page, "老後に備えたい");
    await page.getByTestId("ask-other-input").fill("null");
    await page.getByTestId("ask-other-send").click();
    await page.getByTestId("choose-fixed-60").waitFor();
  });

  it("道具なしで番が終わると、続きのカードが出て、そこから案へ進める", async () => {
    const page = await start();
    await send(page, "契約の一覧を見せて");
    await page.locator("[data-tool=continue] .agent").waitFor();
    expect(await page.locator("[data-tool=continue] .agent").textContent()).toMatch(/契約は \d+ 件/);
    await send(page, "老後に備えたい");
    await page.getByTestId("ask-option-0").waitFor();
  });

  it("新しい申し込みで、案のカードから始め直し、別の nonce で申し込める。完了の後は、照合が押さなくても出る", async () => {
    const page = await start();
    expect(await page.getByTestId("new-application").isVisible()).toBe(false);
    await alice!.chat("老後に備えたい");
    const first = await alice!.nonce;
    await page.getByTestId("new-application").click();
    await page.getByTestId("free-input").waitFor();
    expect(await page.getByTestId("offers").count()).toBe(0);
    expect(await page.locator("#steps li[aria-current]").getAttribute("data-step")).toBe("consult");

    await alice!.chat("老後に備えたい");
    const second = await alice!.nonce;
    expect(second).not.toBe(first);
    await alice!.choose("fixed-60");
    expect(await alice!.approveIfShows(PLANS["fixed-60"]!)).toBe(true);
    await expect.poll(() => page.getByTestId(`reconcile-${second}`).getAttribute("data-status"), { timeout: 15_000 }).toBe("match");
    // 完了の後は、確かめずに始め直せる
    await page.getByTestId("new-application").click();
    await page.getByTestId("free-input").waitFor();
    expect(await page.getByTestId("new-confirm-box").isVisible()).toBe(false);
  });

  it("提出の途中の新しい申し込みは、契約になりうることを確かめてから始め直す", async () => {
    const page = await start();
    await alice!.chat("老後に備えたい");
    await alice!.choose("fixed-60");
    await page.getByTestId("sign-intent").click();
    await page.getByTestId("sign-application").waitFor();
    // 提出の要求を遅らせて、途中の状態を作る
    await page.route("**/agui", async (route) => {
      await new Promise((r) => setTimeout(r, 3000));
      await route.continue().catch(() => undefined);
    });
    await page.getByTestId("sign-application").click();
    await page.getByTestId("agent-status").and(page.locator("[data-state=busy]")).waitFor();
    await page.getByTestId("new-application").click();
    await page.getByTestId("new-confirm-box").waitFor();
    await page.getByTestId("new-back").click();
    expect(await page.getByTestId("new-confirm-box").isVisible()).toBe(false);
    await page.getByTestId("new-application").click();
    await page.getByTestId("new-confirm").click();
    await page.getByTestId("free-input").waitFor();
    expect(await page.locator("[data-tool=application]").count()).toBe(0);
  });

  it("トークンが切れると、token-guard が断り、ログインし直しへ案内する", async () => {
    const page = await start();
    // 期限切れと同じく、token-guard が断るトークンに替える
    await page.evaluate(() => {
      const session = JSON.parse(sessionStorage.getItem("session")!);
      sessionStorage.setItem("session", JSON.stringify({ ...session, token: "expired" }));
    });
    await page.reload();
    await send(page, "老後に備えたい");
    await page.getByTestId("relogin").click();
    await page.getByTestId("free-input").waitFor({ timeout: 30_000 });
    expect(await alice!.whoami()).toBe("alice");
  });

  it("署名した申込書を送れなかったときは、写しを残さない", async () => {
    const page = await start();
    await alice!.chat("老後に備えたい");
    const nonce = await alice!.nonce;
    await alice!.choose("fixed-60");
    await page.getByTestId("sign-intent").click();
    await page.getByTestId("sign-application").waitFor();
    // 提出の要求が、トークンの期限切れで断られる
    await page.route("**/agui", (route) => route.fulfill({ status: 401, headers: { "access-control-allow-origin": alice!.app }, json: { error: "expired" } }));
    await page.getByTestId("sign-application").click();
    await page.getByTestId("relogin").waitFor();
    expect(await page.evaluate(() => localStorage.getItem("copies:alice") ?? "[]")).not.toContain(nonce);
  });
});

describe("サインアウト", () => {
  it("secure: 顧客がサインアウトすると、次のログインで、ログインサーバーがまた本人を確かめる", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    await alice.page.getByTestId("signout").click();
    await alice.page.getByTestId("login").waitFor();
    expect(await alice.page.getByTestId("whoami").isVisible()).toBe(false);
    await alice.page.getByTestId("login").click();
    await alice.page.locator("#username").waitFor();
  });

  it("secure: ログインサーバーが再起動して鍵が替わっていても、サインアウトで行き止まりにならない", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    // ログインサーバーが確かめられない ID トークンを持つ状態を作る
    await alice.page.evaluate(() => {
      const session = JSON.parse(sessionStorage.getItem("session")!);
      sessionStorage.setItem("session", JSON.stringify({ ...session, idToken: "unknown" }));
    });
    await alice.page.getByTestId("signout").click();
    // ID トークンを示せないので、ログインサーバーの確認の画面で、利用者が終わらせる
    await alice.page.locator("#kc-logout").click();
    await alice.page.getByTestId("login").waitFor();
    expect(alice.page.url()).toBe(`${alice.app}/`);
  });

  it("secure: 顧客のまま監査の画面を開くと断られ、サインアウトして、同じブラウザで監査の担当に替われる", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    const audit = publicOrigin("secure", "audit");
    await alice.page.goto(audit);
    await alice.page.getByTestId("forbidden").waitFor();
    await alice.page.getByTestId("signout").click();
    await alice.page.locator("#username").fill("kansa");
    await alice.page.locator("#password").fill("demo");
    await alice.page.locator("button[type=submit]").click();
    await alice.page.waitForURL(`${audit}/**`);
    expect(await alice.page.locator(".who").first().textContent()).toContain("kansa");
    // 監査の担当もサインアウトすると、次に開いたときに、またログインを求められる
    await alice.page.getByTestId("signout").click();
    await alice.page.locator("#username").waitFor();
  });
});

describe("監査の画面", () => {
  it("secure: 顧客は、ログインサーバーにログインできても、監査の画面を見られない", async () => {
    auditor = new BrowserAuditor("secure", "alice");
    expect(await auditor.open()).toBe(403);
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
