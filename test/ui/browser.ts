// 画面のテストの部品。ブラウザの顧客を演じる。passkey は、CDP の仮想の認証器が持つ（D-28）。
// ブラウザは、入口（http://app.<ns>.localhost）から、ほかの利用者と同じ経路で画面を使う。
import { chromium, type Browser, type BrowserContext, type Page, type Route } from "playwright-core";
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

/** 案の一覧（Store の CATALOG と同じ）。 */
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
  /** 画面が受け取った提示の nonce（被害の判定に使う）。 */
  nonce = "";

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
    // 営業 AI エージェントの返答から、提示の nonce を控える
    this.page.on("response", async (res) => {
      if (res.url() === `${publicOrigin(this.ns, "agent")}/chat` && res.ok()) {
        const nonce = ((await res.json().catch(() => ({}))) as Json).offer?.nonce;
        if (nonce) this.nonce = nonce;
      }
    });
    await this.page.goto(this.app);
    return this;
  }

  async close() {
    await this.context?.close();
  }

  /** 取決めに同意して、認可サーバーのログイン画面で、固定ユーザーのパスワードを入れる。 */
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
    await this.page.getByTestId("chat-send").waitFor();
  }

  /** ログインと登録までを済ませる。 */
  async ready(): Promise<this> {
    await this.open();
    await this.login();
    if ((await this.whoami()) !== this.user) throw new Error(`ログインできない: ${await this.error()}`);
    await this.registerPasskey();
    return this;
  }

  /** 相談して、案が出るまで待つ。Claude が道具を呼ばなかったときは、1 度だけ頼み直す。 */
  async chat(message = "老後に備えて、個人年金保険の案を見せてください。") {
    for (const text of [message, "get_offers を使って、案を示してください。"]) {
      await this.page.getByTestId("chat-input").fill(text);
      await this.page.getByTestId("chat-send").click();
      const shown = this.page.locator("[data-testid^=plan-]").first();
      await this.page.locator("[data-testid^=plan-]:visible, [data-testid=error]:visible").first().waitFor({ timeout: 120_000 }).catch(() => undefined);
      if (await shown.isVisible()) return;
      if (await this.page.getByTestId("error").isVisible()) return;
    }
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
    await this.page.getByTestId("sign-intent").waitFor();
  }

  /** 画面に出ている確認の内容（意向確認書面か申込書）。 */
  async confirmation(step: "intent" | "application"): Promise<string> {
    return (await this.page.getByTestId(`${step}-confirm`).textContent()) ?? "";
  }

  /** 選んだ案の名前が出ていて、ほかの案の名前が出ていないか（顧客が画面を読む判断を演じる）。 */
  private async shows(step: "intent" | "application", chosen: Plan): Promise<boolean> {
    const text = await this.confirmation(step);
    const others = Object.values(PLANS).filter((p) => p.id !== chosen.id);
    return text.includes(chosen.name) && !others.some((p) => text.includes(p.name));
  }

  /** 意向確認書面と申込書を順に読み、どちらも選んだ案なら署名する。違えば、そこでやめる。 */
  async approveIfShows(chosen: Plan): Promise<boolean> {
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
    await this.page.locator("[data-testid=submit-result]:has-text('申し込みました'), [data-testid=error]:visible").first().waitFor();
    return true;
  }

  async submitResult(): Promise<string> {
    return (await this.page.getByTestId("submit-result").textContent()) ?? "";
  }

  /** 受信箱を照合し、その nonce の結果を返す。 */
  async reconcile(nonce = this.nonce): Promise<string | undefined> {
    await this.page.getByTestId("check-inbox").click();
    const item = this.page.getByTestId(`reconcile-${nonce}`);
    await item.waitFor({ timeout: 10_000 }).catch(() => undefined);
    return (await item.count()) ? ((await item.getAttribute("data-status")) ?? undefined) : undefined;
  }

  /** 営業 AI エージェントの返答を書き換える（乗っ取られた営業 AI エージェントの役）。 */
  async rewriteAgent(path: "/chat" | "/prepare", edit: (body: Json) => Json) {
    await this.page.route(`${publicOrigin(this.ns, "agent")}${path}`, async (route: Route) => {
      if (route.request().method() !== "POST") return route.continue();
      try {
        const res = await route.fetch();
        const body = (await res.json()) as Json;
        await route.fulfill({ response: res, json: res.ok() ? edit(body) : body });
      } catch (e) {
        // 書き換えに失敗したら、要求を止めて、画面に失敗を出す（待ち続けない）
        console.error(`返答を書き換えられない: ${(e as Error).message}`);
        await route.abort();
      }
    });
  }
}
