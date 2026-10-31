// token-guard の設定。サービスごとに環境変数で与える（architecture の 2-2、D-16）。
const env = (name: string, fallback?: string): string => {
  const v = process.env[name] ?? fallback;
  if (v === undefined) throw new Error(`環境変数 ${name} がありません`);
  return v;
};

const trustDomain = env("TRUST_DOMAIN", "gekko11.internal");
const namespace = env("NAMESPACE");

export const spiffeId = (service: string) => `spiffe://${trustDomain}/ns/${namespace}/sa/${service}`;

export const config = {
  port: Number(env("TOKEN_GUARD_PORT", "9100")),
  /** このサービスの名前。受け取るトークンの aud で、替えるときの client_id。 */
  service: env("SERVICE"),
  issuer: env("ISSUER"),
  /** 受け口で求める証明: 顧客のアプリからは DPoP、サービスからは mTLS の証明書（D-7）。 */
  ingress: env("INGRESS_PROOF") as "dpop" | "mtls",
  /** このサービスを呼んでよい者（D27）。 */
  allowedCallers: env("ALLOWED_CALLERS", "").split(",").filter(Boolean).map(spiffeId),
  /** 次の段の宛先。替えるときの audience。 */
  next: process.env.NEXT_SERVICE,
  /** 認可サーバーへの出口（Envoy が SVID で mTLS をかける）。 */
  authUrl: env("AUTH_EGRESS_URL", "http://127.0.0.1:15101"),
};
