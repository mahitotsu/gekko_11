// 受け口の確かめ（architecture の 2-2 の token-guard、scenarios の D26、D27）。
import { createHash } from "node:crypto";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import { config } from "./config.ts";
import { enabled } from "./defenses.ts";

export class Refusal extends Error {
  readonly status: 401 | 403;
  constructor(status: 401 | 403, message: string) {
    super(message);
    this.status = status;
  }
}

export interface Peer {
  spiffeId?: string;
  /** 相手の証明書の SHA-256（16 進）。Envoy の XFCC の Hash。 */
  hash?: string;
}

export interface Checked {
  token: string;
  claims: JWTPayload & { cnf?: { jkt?: string; "x5t#S256"?: string }; act?: unknown };
  peer: Peer;
}

export interface IngressRequest {
  method: string;
  url: string;
  authorization?: string;
  dpop?: string;
  xfcc?: string;
}

const jwks = createRemoteJWKSet(new URL(config.jwksUrl), { cooldownDuration: 0 });
const otherJwks = config.otherJwksUrl ? createRemoteJWKSet(new URL(config.otherJwksUrl), { cooldownDuration: 0 }) : undefined;
/** 悪い確かめ（D29 を外す）: どちらの発行者の鍵でも認める。 */
const anyIssuerKey: JWTVerifyGetKey = async (header, token) => {
  try {
    return await jwks(header, token);
  } catch (e) {
    if (!otherJwks) throw e;
    return otherJwks(header, token);
  }
};
const b64url = (bytes: Buffer) => bytes.toString("base64url");

/** Envoy が付ける XFCC（SANITIZE_SET）から、相手の SPIFFE ID と証明書のハッシュを読む。 */
export function parseXfcc(header: string | undefined): Peer {
  if (!header) return {};
  const peer: Peer = {};
  for (const part of header.split(",")[0]!.split(";")) {
    const i = part.indexOf("=");
    const key = part.slice(0, i);
    const value = part.slice(i + 1).replace(/^"|"$/g, "");
    if (key === "URI") peer.spiffeId = value;
    if (key === "Hash") peer.hash = value;
  }
  return peer;
}

export async function checkIngress(req: IngressRequest): Promise<Checked> {
  const peer = parseXfcc(req.xfcc);
  const { checks } = config;
  // サービスからの受け口と、呼んでよい相手を決めた DPoP の受け口（営業 AI エージェント。D-41）は、相手の証明書を確かめる
  if (config.ingress === "mtls" || config.allowedCallers.length > 0) {
    if (!peer.spiffeId) throw new Refusal(401, "相手の証明書がない");
    if (enabled(checks.caller) && !config.allowedCallers.includes(peer.spiffeId)) {
      throw new Refusal(403, `呼んでよい相手ではない: ${peer.spiffeId}`);
    }
  }

  const scheme = config.ingress === "dpop" ? "DPoP" : "Bearer";
  const token = req.authorization?.match(new RegExp(`^${scheme} (.+)$`))?.[1];
  if (!token) throw new Refusal(401, `Authorization: ${scheme} がない`);

  let claims: Checked["claims"];
  try {
    claims = await verifyToken(token);
  } catch (e) {
    throw new Refusal(401, `トークンを確かめられない: ${(e as Error).message}`);
  }

  if (checks.introspect && enabled(checks.introspect)) await introspect(token);

  if (enabled(checks.binding)) {
    if (config.ingress === "mtls") {
      const bound = claims.cnf?.["x5t#S256"];
      if (!bound || !peer.hash || bound !== b64url(Buffer.from(peer.hash, "hex"))) {
        throw new Refusal(401, "トークンが、相手の証明書に結ばれていない");
      }
    } else {
      await checkDpop(req, token, claims.cnf?.jkt);
    }
  }
  return { token, claims, peer };
}

const HUNDRED_YEARS = 60 * 60 * 24 * 365 * 100;

/**
 * トークンの署名・iss・aud・exp・typ を確かめる。vulnerable では、防御の ID ごとに外せる。
 * 署名を外すと、中身を読むだけになる（alg=none も通る）。
 */
async function verifyToken(token: string): Promise<Checked["claims"]> {
  const { checks } = config;
  if (checks.verify && !enabled(checks.verify)) return decodeJwt(token);
  const signature = checks.signature === undefined || enabled(checks.signature);
  const aud = checks.aud === undefined || enabled(checks.aud);
  const exp = checks.exp === undefined || enabled(checks.exp);
  const typ = checks.typ === undefined || enabled(checks.typ);
  const issuer = checks.issuer === undefined || enabled(checks.issuer);
  if (signature) {
    const { payload } = await jwtVerify(token, issuer ? jwks : anyIssuerKey, {
      algorithms: ["RS256"],
      issuer: issuer ? config.issuer : undefined,
      audience: aud ? config.service : undefined,
      typ: typ ? "at+jwt" : undefined,
      requiredClaims: ["sub"],
      clockTolerance: exp ? 0 : HUNDRED_YEARS,
    });
    return payload;
  }
  const payload = decodeJwt(token);
  const auds = [payload.aud ?? []].flat();
  if (aud && !auds.includes(config.service)) throw new Error("aud が違う");
  if (exp && (payload.exp ?? 0) * 1000 < Date.now()) throw new Error("期限切れ");
  if (typ && decodeProtectedHeader(token).typ !== "at+jwt") throw new Error("typ が違う");
  return payload;
}

/** 取り次いだ窓口とトークンを受け取ったクライアントが、全て登録されていて外れていないか（D10、P-13）。 */
async function introspect(token: string): Promise<void> {
  const res = await fetch(`${config.authUrl}/oauth2/introspect`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ token, client_id: config.service }),
  });
  const body = (await res.json().catch(() => ({}))) as { active?: boolean };
  if (!body.active) throw new Refusal(403, "トークンが無効か、取り次いだ窓口の登録が外れている");
}

const seenJti = new Map<string, number>();

/** DPoP の proof を確かめる（RFC 9449 の 4.3）。 */
async function checkDpop(req: IngressRequest, token: string, jkt: string | undefined): Promise<void> {
  if (!req.dpop) throw new Refusal(401, "DPoP の proof がない");
  if (!jkt) throw new Refusal(401, "トークンが、DPoP の鍵に結ばれていない");
  try {
    const header = decodeProtectedHeader(req.dpop);
    const jwk = header.jwk as JWK | undefined;
    if (!jwk || !header.alg) throw new Error("jwk がない");
    const { payload } = await jwtVerify(req.dpop, await importJWK(jwk, header.alg), {
      typ: "dpop+jwt",
      maxTokenAge: "60s",
    });
    if (payload.htm !== req.method) throw new Error("htm が違う");
    if (payload.htu !== req.url) throw new Error(`htu が違う: ${String(payload.htu)}`);
    if (payload.ath !== b64url(createHash("sha256").update(token).digest())) throw new Error("ath が違う");
    if ((await calculateJwkThumbprint(jwk)) !== jkt) throw new Error("鍵が、トークンの cnf.jkt と違う");
    const now = Date.now();
    for (const [k, exp] of seenJti) if (exp < now) seenJti.delete(k);
    if (!payload.jti || seenJti.has(payload.jti)) throw new Error("jti が使い回された");
    seenJti.set(payload.jti, now + 120_000);
  } catch (e) {
    throw new Refusal(401, `DPoP の proof を確かめられない: ${(e as Error).message}`);
  }
}
