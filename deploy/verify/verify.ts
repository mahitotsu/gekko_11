// 段 0 の確かめ。手元から kubectl exec で probe を動かし、secure と vulnerable で同じ操作の結果を比べる。
// 使い方: node deploy/verify/verify.ts   （deploy/cluster.sh verify から呼ぶ）
import { execFileSync } from "node:child_process";

type Ns = "secure" | "vulnerable";
type Json = Record<string, any>;

function probe(ns: Ns, who: string, command: string, args: object = {}): Json {
  const out = execFileSync(
    "kubectl",
    ["-n", ns, "exec", `deploy/${who}`, "-c", "probe", "--", "node", "deploy/verify/probe.ts", command, JSON.stringify(args)],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  return JSON.parse(out.trim().split("\n").at(-1)!);
}

const hexToB64url = (hex: string) => Buffer.from(hex, "hex").toString("base64url");
const aud = (claims: Json) => (Array.isArray(claims.aud) ? claims.aud.join(",") : claims.aud);
const actChain = (act: Json | undefined): string[] => (act ? [act.sub, ...actChain(act.act)] : []);

interface Row {
  id: string;
  what: string;
  expected: Record<Ns, string>;
  actual: Partial<Record<Ns, string>>;
}

const rows: Row[] = [];
const row = (id: string, what: string, secure: string, vulnerable = secure) => {
  const r: Row = { id, what, expected: { secure, vulnerable }, actual: {} };
  rows.push(r);
  return r;
};
const PASS = "通る";
const REFUSE = "拒否";
const outcome = (status: number) => (status === 200 ? PASS : `${REFUSE}(${status})`);
const sameKind = (expected: string, actual: string) => actual.startsWith(expected);

const r1 = row("1", "A に cnf.jkt と may_act（sales-agent）が入る", "入る");
const r2a = row("2a", "A を正しい DPoP の proof で sales-agent に出す", PASS);
const r2b = row("2b", "A を DPoP の proof なしで出す（D26）", REFUSE, PASS);
const r2c = row("2c", "A を別の鍵の proof で出す（D26）", REFUSE, PASS);
const r3 = row("3", "B: aud=insurer-mcp、sales-agent の SVID に結ばれ、act=sales-agent、may_act=insurer-mcp", "入る");
const r4 = row("4", "C: aud=insurer-backend、insurer-mcp の SVID に結ばれ、act が入れ子", "入る");
const r5 = row("5", "insurer-backend が sub と act の連鎖を受け取る", "alice / insurer-mcp,sales-agent");
const r6a = row("6a", "事務サービスが、営業 AI エージェント宛ての A を替える", REFUSE);
const r6b = row("6b", "営業 AI エージェントが、段を飛ばした宛先を求める", REFUSE);
const r6c = row("6c", "登録のない SPIFFE ID（intruder）が、トークンを求める", REFUSE);
const r6d = row("6d", "証明書なしで、替えを頼む", REFUSE);
const r6e = row("6e", "actor_token なしで、替えを頼む", REFUSE);
const r7a = row("7a", "C を、結ばれた証明書の持ち主（mcp-1）が出す", PASS);
const r7b = row("7b", "盗んだ C を、結ばれた鍵と違う鍵の持ち主（mcp-2）から出す（D26）", REFUSE, PASS);
const r8 = row("8", "C を、許していない SPIFFE ID（intruder）から出す（D27）", REFUSE, PASS);
const r9a = row("9a", "C を、証明書なしで出す", REFUSE);
const r9b = row("9b", "もう一方の名前空間の insurer-backend につなぐ", "つながらない");

for (const ns of ["secure", "vulnerable"] as Ns[]) {
  const a = probe(ns, "probe-sales-agent", "customer-token", { user: "alice" });
  const ac = probe(ns, "probe-sales-agent", "decode", { token: a.token });
  r1.actual[ns] = ac.cnf?.jkt === a.jkt && ac.may_act?.sub === "sales-agent" && aud(ac) === "sales-agent" ? "入る" : JSON.stringify(ac);

  const chain = probe(ns, "probe-sales-agent", "call-sales-agent", { token: a.token, dpopKey: a.dpopKey, proof: "good" });
  r2a.actual[ns] = outcome(chain.status);
  for (const [r, proof] of [[r2b, "none"], [r2c, "other-key"]] as const) {
    const fresh = probe(ns, "probe-sales-agent", "customer-token", { user: "alice" });
    r.actual[ns] = outcome(probe(ns, "probe-sales-agent", "call-sales-agent", { token: fresh.token, dpopKey: fresh.dpopKey, proof }).status);
  }

  const mcp = chain.body?.next?.body;
  const backend = mcp?.next?.body;
  const b = mcp?.verified;
  const c = backend?.verified;
  r3.actual[ns] =
    b &&
    aud(b.claims) === "insurer-mcp" &&
    b.claims.cnf?.["x5t#S256"] === hexToB64url(b.peer.hash) &&
    b.peer.spiffeId.endsWith(`/ns/${ns}/sa/sales-agent`) &&
    actChain(b.claims.act).join(",") === "sales-agent" &&
    b.claims.may_act?.sub === "insurer-mcp"
      ? "入る"
      : JSON.stringify(mcp ?? chain);
  r4.actual[ns] =
    c &&
    aud(c.claims) === "insurer-backend" &&
    c.claims.cnf?.["x5t#S256"] === hexToB64url(c.peer.hash) &&
    c.peer.spiffeId.endsWith(`/ns/${ns}/sa/insurer-mcp`) &&
    actChain(c.claims.act).join(",") === "insurer-mcp,sales-agent" &&
    !c.claims.may_act
      ? "入る"
      : JSON.stringify(backend ?? mcp ?? chain);
  r5.actual[ns] = c ? `${c.claims.sub} / ${actChain(c.claims.act).join(",")}` : "なし";

  // 乗っ取られた複製（probe）が、自分の SVID でトークンを替える
  const salesActor = probe(ns, "probe-sales-agent", "client-credentials").body.access_token;
  const mcpActor = probe(ns, "probe-mcp-1", "client-credentials").body.access_token;
  r6a.actual[ns] = outcome(probe(ns, "probe-mcp-1", "exchange", { subject: a.token, actor: mcpActor, audience: "insurer-backend" }).status);
  r6b.actual[ns] = outcome(probe(ns, "probe-sales-agent", "exchange", { subject: a.token, actor: salesActor, audience: "insurer-backend" }).status);
  r6c.actual[ns] = outcome(probe(ns, "probe-intruder", "client-credentials").status);
  r6d.actual[ns] = outcome(
    probe(ns, "probe-sales-agent", "exchange", { subject: a.token, actor: salesActor, audience: "insurer-mcp", clientCert: false }).status,
  );
  r6e.actual[ns] = outcome(probe(ns, "probe-sales-agent", "exchange", { subject: a.token, audience: "insurer-mcp" }).status);

  const bToken = probe(ns, "probe-sales-agent", "exchange", { subject: a.token, actor: salesActor, audience: "insurer-mcp" }).body.access_token;
  const cToken = probe(ns, "probe-mcp-1", "exchange", { subject: bToken, actor: mcpActor, audience: "insurer-backend" }).body.access_token;
  const callBackend = (who: string, clientCert = true) => {
    try {
      return outcome(probe(ns, who, "call-service", { service: "insurer-backend", token: cToken, clientCert }).status);
    } catch {
      return `${REFUSE}(TLS)`;
    }
  };
  r7a.actual[ns] = callBackend("probe-mcp-1");
  r7b.actual[ns] = callBackend("probe-mcp-2");
  r8.actual[ns] = callBackend("probe-intruder");
  r9a.actual[ns] = callBackend("probe-mcp-1", false);
  const other: Ns = ns === "secure" ? "vulnerable" : "secure";
  const reach = probe(ns, "probe-mcp-1", "reach-other-namespace", { namespace: other, service: "insurer-backend" });
  r9b.actual[ns] = reach.connected ? `つながる(${reach.status})` : "つながらない";
}

let failed = 0;
console.log("| # | 確かめること | secure | vulnerable |\n|---|---|---|---|");
for (const r of rows) {
  const cell = (ns: Ns) => {
    const ok = sameKind(r.expected[ns], r.actual[ns] ?? "");
    if (!ok) failed++;
    return `${ok ? "OK" : "NG"} ${r.actual[ns]}${ok ? "" : `（期待: ${r.expected[ns]}）`}`;
  };
  console.log(`| ${r.id} | ${r.what} | ${cell("secure")} | ${cell("vulnerable")} |`);
}
console.log(failed === 0 ? "\n全て期待どおり" : `\n期待と違う: ${failed} 件`);
process.exit(failed === 0 ? 0 : 1);
