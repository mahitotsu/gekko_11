// token-guard の設定。サービスごとに環境変数で与える（architecture の 2-2、D-16）。
const env = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (v === undefined) throw new Error(`環境変数 ${name} がありません`);
  return v;
};

const trustDomain = env("TRUST_DOMAIN", "gekko11.internal");
const namespace = env("NAMESPACE");

export const spiffeId = (service: string) => `spiffe://${trustDomain}/ns/${namespace}/sa/${service}`;

/** 確かめの種類ごとに、そのサービスで当たる防御の ID（scenarios の 2-3）。 */
export interface Checks {
  /** トークンを全く確かめない（D20）。 */
  verify?: string;
  signature?: string;
  exp?: string;
  aud?: string;
  typ?: string;
  /** 自分の段の発行者だけを認める（D29）。 */
  issuer?: string;
  /** 出口で、トークンを替える（D2）。 */
  exchange?: string;
  /** 受け口で、取り次いだ窓口の登録が有効かを、認可サーバーに問い合わせる（D10）。 */
  introspect?: string;
  /** 送信者の鍵への結び付け（D26）と、呼ぶ相手の SPIFFE ID（D27）は、どのサービスでも当たる。 */
  binding: string;
  caller: string;
}

const CHECKS: Record<string, Omit<Checks, "binding" | "caller">> = {
  "sales-agent": { verify: "D20" },
  "insurer-mcp": { aud: "D1", typ: "D1", issuer: "D29", exchange: "D2" },
  "insurer-backend": { signature: "D5", exp: "D6", aud: "D7", typ: "D8", issuer: "D29", introspect: "D10" },
};

const service = env("SERVICE");
const checks: Checks = { ...CHECKS[service], binding: "D26", caller: "D27" };

export const config = {
  port: Number(env("TOKEN_GUARD_PORT", "9100")),
  adminPort: Number(env("TOKEN_GUARD_ADMIN_PORT", "9090")),
  /** このサービスの名前。受け取るトークンの aud で、替えるときの client_id。 */
  service,
  /** 受け取るトークンの発行者。営業 AI エージェントはログインサーバー（A）、ほかは認可サーバー（B、C）である（D-35）。 */
  issuer: env("ISSUER"),
  /** 発行者の公開鍵（Envoy の出口を通す）。 */
  jwksUrl: env("JWKS_URL", `${env("AUTH_EGRESS_URL", "http://127.0.0.1:15101")}/oauth2/jwks`),
  /** もう一方の発行者の公開鍵。vulnerable で D29 を外すときだけ使う。 */
  otherJwksUrl: process.env.OTHER_JWKS_URL,
  /** DPoP で呼ばれる名前。htu は、この名前とパスで照らす。営業 AI エージェントは、BFF が呼ぶ内部の名前である（D-41）。 */
  publicOrigin: process.env.PUBLIC_ORIGIN,
  /** 受け口で求める証明: 顧客のアプリからは DPoP、サービスからは mTLS の証明書（D-7）。 */
  ingress: env("INGRESS_PROOF") as "dpop" | "mtls",
  /** このサービスを呼んでよい者（D27）。 */
  allowedCallers: env("ALLOWED_CALLERS", "").split(",").filter(Boolean).map(spiffeId),
  /** 次の段の宛先。替えるときの audience。 */
  next: process.env.NEXT_SERVICE,
  /** 認可サーバーへの出口（Envoy が SVID で mTLS をかける）。 */
  authUrl: env("AUTH_EGRESS_URL", "http://127.0.0.1:15101"),
  checks,
  /** このサービスで外せる防御の ID。 */
  defenseIds: [...new Set(Object.values(checks).filter((v): v is string => typeof v === "string"))],
};
