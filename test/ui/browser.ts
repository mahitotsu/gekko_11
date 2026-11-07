// 画面のテストの部品。ブラウザの顧客を演じる。passkey は、CDP の仮想の認証器が持つ（D-28）。
// ブラウザは、入口（http://app.<ns>.localhost）から、ほかの利用者と同じ経路で画面を使う。
import { chromium, type Browser, type BrowserContext, type Page, type Route } from "playwright-core";
import { parseSse } from "../../packages/customer-app/web/agui.ts";
import { publicOrigin, type Json, type Ns } from "../cluster/world.ts";

export const PLAYWRIGHT_VERSION = "1.64.1";
export const BROWSER_PORT = 3333;

let browser: Browser | undefined;
async function connect(): Promise<Browser> {
  if (!browser?.isConnected()) browser = await chromium.connect(`ws://127.0.0.1:${BROWSER_PORT}/`);
  return browser;
}

/** 見えている要素のどれかが出るまで待つ（隠れた要素を、待つ相手にしない）。 */
const anyVisible = (page: Page, ...testIds: string[]) =>
  page.locator(testIds.map((id) => `[data-testid=${id}]:visible`).join(", ")).first();

export interface Plan {
  id: string;
  name: string;
  kind: string;
  benefit: number;
  monthly: number;
}

/** 既定の条件の案（台本が組み立てる案。world.ts の DEFAULT_PLANS と同じ）。 */
export const PLANS: Record<string, Plan> = {
  "fixed-60": { id: "fixed-60", name: "確定年金 10年・年額60万円", kind: "fixed", benefit: 600_000, monthly: 20_000 },
  "fixed-120": { id: "fixed-120", name: "確定年金 10年・年額120万円", kind: "fixed", benefit: 1_200_000, monthly: 40_000 },
  "life-120": { id: "life-120", name: "終身年金・年額120万円", kind: "lifetime", benefit: 1_200_000, monthly: 60_000 },
};

/** ブラウザの顧客。新しい端末（ブラウザのコンテキスト）で、passkey を持つ認証器を 1 つ付ける。 */
export class BrowserCustomer {
  readonly ns: Ns;
  readonly user: string;
  context!: BrowserContext;
  page!: Page;
  constructor(ns: Ns, user: string) {
    this.ns = ns;
    this.user = user;
  }

  get app() {
    return publicOrigin(this.ns, "app");
  }

  async open(): Promise<this> {
    this.context = await (await connect()).newContext();
    this.page = await this.context.newPage();
    const cdp = await this.context.newCDPSession(this.page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });
    await this.page.goto(this.app);
    return this;
  }

  async close() {
    await this.context?.close();
  }

  /** 取決めに同意して、ログインサーバーのログイン画面で、固定ユーザーのパスワードを入れる。 */
  async login() {
    await this.page.getByTestId("login").click();
    await this.page.locator("#username").fill(this.user);
    await this.page.locator("#password").fill("demo");
    await this.page.locator("button[type=submit]").click();
    await this.page.waitForURL(`${this.app}/**`);
  }

  async whoami(): Promise<string | null> {
    await anyVisible(this.page, "whoami", "error").waitFor();
    return (await this.page.getByTestId("whoami").isVisible()) ? this.page.getByTestId("whoami").textContent() : null;
  }

  async error(): Promise<string | null> {
    return (await this.page.getByTestId("error").isVisible()) ? this.page.getByTestId("error").textContent() : null;
  }

  async registerPasskey() {
    await this.page.getByTestId("register-passkey").click();
    await this.page.getByTestId("free-send").waitFor();
  }

  /** ログインと登録までを済ませる。 */
  async ready(): Promise<this> {
    await this.open();
    await this.login();
    if ((await this.whoami()) !== this.user) throw new Error(`ログインできない: ${await this.error()}`);
    await this.registerPasskey();
    return this;
  }

  /** 営業 AI エージェントの番が終わるまで待つ。 */
  async idle(timeout = 120_000) {
    await this.page.locator("[data-testid=agent-status][data-state=idle]").waitFor({ state: "attached", timeout });
  }

  /** 画面が受け取った提示の nonce（被害の判定に使う）。 */
  get nonce(): Promise<string> {
    return this.page.getByTestId("offers").getAttribute("data-nonce").then((n) => n ?? "");
  }

  /**
   * 相談して、案が示されるまで会話を進める。営業 AI エージェントの質問には、最初の選択肢で答える。
   * Claude が案を示さずに番を終えたときは、1 度だけ頼み直す。
   */
  async chat(message = "老後に備えて、個人年金保険を考えています。") {
    for (const text of [message, "保険会社の案を示して、選ばせてください。"]) {
      await this.page.getByTestId("free-input").fill(text);
      await this.page.getByTestId("free-send").click();
      for (let i = 0; i < 6; i++) {
        await this.page.locator("[data-testid^=plan-]:visible, [data-testid=ask-option-0]:visible:enabled, [data-testid=error]:visible, [data-testid=agent-status][data-state=idle]")
          .first().waitFor({ timeout: 120_000 }).catch(() => undefined);
        if (await this.page.locator("[data-testid^=plan-]").first().isVisible()) return;
        if (await this.page.getByTestId("error").isVisible()) return;
        const ask = this.page.locator("[data-testid=ask-option-0]:enabled");
        if (await ask.count()) {
          await ask.click();
          await this.page.waitForTimeout(300);
          continue;
        }
        if ((await this.page.getByTestId("agent-status").getAttribute("data-state")) === "idle") break;
      }
    }
  }

  /** 今開いている案のカードの、案の番号と名前。 */
  async shownPlans(): Promise<Pick<Plan, "id" | "name">[]> {
    return this.page.locator("[data-testid^=plan-]:visible").evaluateAll((els) =>
      els.map((e) => ({ id: e.getAttribute("data-testid")!.slice(5), name: e.querySelector("strong")!.textContent! })),
    );
  }

  async planIds(): Promise<string[]> {
    return this.page.locator("[data-testid^=plan-]").evaluateAll((els) => els.map((e) => e.getAttribute("data-testid")!.slice(5)));
  }

  async offerWarning(): Promise<string | null> {
    return (await this.page.getByTestId("offer-warning").isVisible()) ? this.page.getByTestId("offer-warning").textContent() : null;
  }

  /** 案を選び、意向確認書面の画面（署名 1/2）が出るまで待つ。 */
  async choose(planId: string) {
    await this.page.getByTestId(`choose-${planId}`).click({ timeout: 5_000 });
    // Claude は、選んだ後にもう 1 つ質問することがある。質問には最初の選択肢で答え、書類を示さずに番を終えたら、1 度だけ頼む
    let asked = false;
    for (let i = 0; i < 6; i++) {
      await this.page.locator("[data-testid=sign-intent]:visible, [data-testid=ask-option-0]:visible:enabled, [data-testid=error]:visible, [data-testid=agent-status][data-state=idle]")
        .first().waitFor({ timeout: 120_000 }).catch(() => undefined);
      if (await this.page.getByTestId("sign-intent").isVisible()) return;
      if (await this.page.getByTestId("error").isVisible()) break;
      const ask = this.page.locator("[data-testid=ask-option-0]:enabled");
      if (await ask.count()) {
        await ask.click();
        await this.page.waitForTimeout(300);
        continue;
      }
      if (!asked && (await this.page.getByTestId("agent-status").getAttribute("data-state")) === "idle") {
        asked = true;
        await this.page.getByTestId("free-input").fill("選んだ案で、意向確認書面を示してください。");
        await this.page.getByTestId("free-send").click();
        await this.page.waitForTimeout(300);
      }
    }
    await this.page.getByTestId("sign-intent").waitFor({ timeout: 5_000 });
  }

  /** 画面に出ている確認の内容（意向確認書面か申込書）。 */
  async confirmation(step: "intent" | "application"): Promise<string> {
    return (await this.page.getByTestId(`${step}-confirm`).textContent()) ?? "";
  }

  /** 選んだ案の名前が出ていて、ほかの案の名前が出ていないか（顧客が画面を読む判断を演じる）。 */
  private async shows(step: "intent" | "application", chosen: Pick<Plan, "id" | "name">): Promise<boolean> {
    const text = await this.confirmation(step);
    const others = Object.values(PLANS).filter((p) => p.id !== chosen.id);
    return text.includes(chosen.name) && !others.some((p) => text.includes(p.name));
  }

  /** 意向確認書面と申込書を順に読み、どちらも選んだ案なら署名する。違えば、そこでやめる。 */
  async approveIfShows(chosen: Pick<Plan, "id" | "name">): Promise<boolean> {
    if (!(await this.shows("intent", chosen))) {
      await this.page.getByTestId("cancel-intent").click();
      return false;
    }
    await this.page.getByTestId("sign-intent").click();
    await anyVisible(this.page, "sign-application", "error").waitFor();
    if (!(await this.page.getByTestId("sign-application").isVisible()) || !(await this.shows("application", chosen))) {
      if (await this.page.getByTestId("cancel-application").isVisible()) await this.page.getByTestId("cancel-application").click();
      return false;
    }
    await this.page.getByTestId("sign-application").click();
    // 営業 AI エージェントが提出して、番を終えるまで待つ
    await this.page.waitForTimeout(300);
    await this.idle();
    return true;
  }

  /** 会話の最後で、今回の申込みを照合し、その結果を返す。 */
  async reconcile(nonce?: string): Promise<string | undefined> {
    nonce ??= await this.nonce;
    await this.page.getByTestId("check-session").click();
    const item = this.page.getByTestId(`reconcile-${nonce}`);
    await item.waitFor({ timeout: 10_000 }).catch(() => undefined);
    return (await item.count()) ? ((await item.getAttribute("data-status")) ?? undefined) : undefined;
  }

  /** 「受信箱と契約」の画面を開き、その nonce の行の結果と、照合した行の数を返す。 */
  async inbox(nonce?: string): Promise<{ status?: string; rows: number }> {
    nonce ??= await this.nonce;
    await this.page.getByTestId("tab-inbox").click();
    const item = this.page.getByTestId(`inbox-${nonce}`);
    await item.waitFor({ timeout: 10_000 }).catch(() => undefined);
    const rows = await this.page.locator("[data-testid^=inbox-]:not([data-testid=inbox-alert])").count();
    return { status: (await item.count()) ? ((await item.getAttribute("data-status")) ?? undefined) : undefined, rows };
  }


  /**
   * 営業 AI エージェントの返答（AG-UI の SSE）の中の、画面側の道具の引数を書き換える（乗っ取られた営業 AI エージェントの役）。
   * edit は、道具の名前と引数を受け取り、新しい引数を返す。
   */
  async rewriteTool(edit: (name: string, args: Json) => Json) {
    await this.page.route(`${publicOrigin(this.ns, "agent")}/agui`, async (route: Route) => {
      if (route.request().method() !== "POST") return route.continue();
      try {
        const res = await route.fetch();
        const events = parseSse(await res.text());
        const names = new Map(events.filter((e) => e.type === "TOOL_CALL_START").map((e) => [e.toolCallId, e.toolCallName]));
        const out = events.map((e) =>
          e.type === "TOOL_CALL_ARGS" && names.has(e.toolCallId) ? { ...e, delta: JSON.stringify(edit(names.get(e.toolCallId)!, JSON.parse(e.delta))) } : e,
        );
        await route.fulfill({ response: res, body: out.map((e) => `data: ${JSON.stringify(e)}\n\n`).join("") });
      } catch (e) {
        // 書き換えに失敗したら、要求を止めて、画面に失敗を出す（待ち続けない）
        console.error(`返答を書き換えられない: ${(e as Error).message}`);
        await route.abort();
      }
    });
  }
}

/** 監査の担当のブラウザ。監査サービスの画面を開くと、認可サーバーのログインへ送られ、戻ってくる（D-31）。 */
export class BrowserAuditor {
  readonly ns: Ns;
  readonly user: string;
  context!: BrowserContext;
  page!: Page;
  constructor(ns: Ns, user = "kansa") {
    this.ns = ns;
    this.user = user;
  }

  /** 監査サービスの画面を開き、ログインする。返すのは、ログインの後の画面の HTTP の状態。 */
  async open(path = "/"): Promise<number | undefined> {
    this.context = await (await connect()).newContext();
    this.page = await this.context.newPage();
    await this.page.goto(`${publicOrigin(this.ns, "audit")}${path}`);
    await this.page.locator("#username").fill(this.user);
    await this.page.locator("#password").fill("demo");
    const [response] = await Promise.all([
      this.page.waitForResponse((r) => r.url().startsWith(publicOrigin(this.ns, "audit")) && r.request().resourceType() === "document" && r.status() !== 302),
      this.page.locator("button[type=submit]").click(),
    ]);
    return response.status();
  }

  /** 契約の突き合わせの画面を開き、結果を返す。Loki に記録が届くまで、決まった回数だけ開き直す。 */
  async contract(nonce: string, until: (status: string, conversationRows: number) => boolean): Promise<{ status: string; conversationRows: number }> {
    let last = { status: "", conversationRows: 0 };
    for (let i = 0; i < 15; i++) {
      await this.page.goto(`${publicOrigin(this.ns, "audit")}/contracts/${nonce}`);
      const status = (await this.page.getByTestId("status").textContent().catch(() => "")) ?? "";
      last = { status, conversationRows: await this.page.locator("[data-testid=conversation] tbody tr").count() };
      if (until(last.status, last.conversationRows)) return last;
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
    return last;
  }

  async close() {
    await this.context?.close();
  }
}
