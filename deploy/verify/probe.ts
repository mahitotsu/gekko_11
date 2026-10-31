// 段 0 の確かめで、クラスタの中から、顧客、乗っ取られた複製、攻撃者の役を演じる。
// 自分の SVID（spiffe-helper が /svid に書き出す）を使うか、証明書なしで呼ぶ。結果は JSON で標準出力に書く。
// 使い方: node probe.ts <コマンド> '<JSON の引数>'
import { createHash, generateKeyPairSync, randomUUID, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { request } from "node:https";
import type { PeerCertificate } from "node:tls";
import { calculateJwkThumbprint, decodeJwt, exportJWK, importJWK, SignJWT, type JWK } from "jose";

const TRUST_DOMAIN = "gekko11.internal";
const SVID_DIR = "/svid";
const ns = process.env.NAMESPACE!;
const self = process.env.SERVICE_ACCOUNT!;
const spiffeId = (sa: string) => `spiffe://${TRUST_DOMAIN}/ns/${ns}/sa/${sa}`;
const origin = (service: string) => `https://${service}.${ns}.svc:${service === "insurer-auth" || service === "sales-agent" ? 8443 : 9443}`;

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** 相手の SPIFFE ID を確かめて呼ぶ。clientCert が真なら、自分の SVID を示す。 */
function call(
  service: string,
  path: string,
  init: { method: string; headers?: Record<string, string>; body?: string; clientCert: boolean },
): Promise<Reply> {
  const url = new URL(path, origin(service));
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: init.method,
        headers: init.headers,
        ca: readFileSync(`${SVID_DIR}/svid_bundle.pem`),
        ...(init.clientCert
          ? { cert: readFileSync(`${SVID_DIR}/svid.pem`), key: readFileSync(`${SVID_DIR}/svid_key.pem`) }
          : {}),
        checkServerIdentity: (_host: string, cert: PeerCertificate) =>
          cert.subjectaltname === `URI:${spiffeId(service)}`
            ? undefined
            : new Error(`相手の SPIFFE ID が違う: ${cert.subjectaltname}`),
      },
      (res) => {
        let body = "";
        res.on("data", (d) => (body += d));
        res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    req.end(init.body);
  });
}

const form = (params: Record<string, string | undefined>) =>
  new URLSearchParams(Object.entries(params).filter((e): e is [string, string] => e[1] !== undefined)).toString();

const FORM = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
const REDIRECT = "http://127.0.0.1:4000/callback";

async function dpopProof(key: SigningKey, jwk: JWK, htm: string, htu: string, token?: string): Promise<string> {
  return new SignJWT({
    htm,
    htu,
    jti: randomUUID(),
    ...(token ? { ath: createHash("sha256").update(token).digest("base64url") } : {}),
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk })
    .setIssuedAt()
    .sign(key);
}

type SigningKey = Parameters<SignJWT["sign"]>[0];

const cookieOf = (r: Reply) => String(r.headers["set-cookie"]?.[0] ?? "").split(";")[0]!;

/** 顧客の役: 固定ユーザーでログインし、認可コードと PKCE と DPoP でトークン A を受け取る。 */
async function customerToken(args: { user?: string }) {
  const verifier = randomUUID() + randomUUID();
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authorize = `/oauth2/authorize?${form({
    response_type: "code",
    client_id: "customer-app",
    scope: "apply",
    redirect_uri: REDIRECT,
    state: "s",
    code_challenge: challenge,
    code_challenge_method: "S256",
  })}`;
  const html = { accept: "text/html" };
  const first = await call("insurer-auth", authorize, { method: "GET", headers: html, clientCert: false });
  let cookie = cookieOf(first);
  const login = await call("insurer-auth", "/login", { method: "GET", headers: { ...html, cookie }, clientCert: false });
  const csrf = login.body.match(/name="_csrf"[^>]*value="([^"]+)"/)?.[1];
  const posted = await call("insurer-auth", "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: form({ username: args.user ?? "alice", password: "demo", _csrf: csrf }),
    clientCert: false,
  });
  cookie = cookieOf(posted) || cookie;
  const resumed = await call("insurer-auth", new URL(String(posted.headers.location)).pathname + new URL(String(posted.headers.location)).search, {
    method: "GET",
    headers: { ...html, cookie },
    clientCert: false,
  });
  const code = new URL(String(resumed.headers.location)).searchParams.get("code");
  if (!code) throw new Error(`認可コードを受け取れない: ${resumed.status} ${String(resumed.headers.location)}`);

  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = await exportJWK(publicKey);
  const proof = await dpopProof(privateKey, jwk, "POST", `${origin("insurer-auth")}/oauth2/token`);
  const res = await call("insurer-auth", "/oauth2/token", {
    method: "POST",
    headers: { ...FORM, dpop: proof },
    body: form({ grant_type: "authorization_code", client_id: "customer-app", code, redirect_uri: REDIRECT, code_verifier: verifier }),
    clientCert: false,
  });
  const body = JSON.parse(res.body) as { access_token?: string };
  return { status: res.status, token: body.access_token, dpopKey: await exportJWK(privateKey), jkt: await calculateJwkThumbprint(jwk) };
}

/** 顧客の役: A を営業 AI エージェントに出す。proof は、正しいもの、なし、別の鍵で作ったもの。 */
async function callSalesAgent(args: { token: string; dpopKey: JWK; proof: "good" | "none" | "other-key" }) {
  const htu = `${origin("sales-agent")}/hop`;
  const headers: Record<string, string> = { authorization: `DPoP ${args.token}` };
  if (args.proof !== "none") {
    const own = { ...args.dpopKey };
    const signer: SigningKey =
      args.proof === "good" ? await importJWK(own, "ES256") : generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    const { d: _d, ...publicJwk } = args.proof === "good" ? own : await exportJWK(signer as KeyObject);
    headers.dpop = await dpopProof(signer, publicJwk, "POST", htu, args.token);
  }
  return reply(await call("sales-agent", "/hop", { method: "POST", headers, clientCert: false }));
}

/** 自分の SVID で、自分のトークン（client_credentials）を受け取る。 */
async function clientCredentials() {
  return reply(
    await call("insurer-auth", "/oauth2/token", {
      method: "POST",
      headers: FORM,
      body: form({ grant_type: "client_credentials", client_id: self }),
      clientCert: true,
    }),
  );
}

/** 自分の SVID で、トークンを替えるよう頼む。 */
async function exchange(args: { subject: string; actor?: string; audience: string; clientCert?: boolean }) {
  return reply(
    await call("insurer-auth", "/oauth2/token", {
      method: "POST",
      headers: FORM,
      body: form({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_id: self,
        subject_token: args.subject,
        subject_token_type: ACCESS_TOKEN,
        actor_token: args.actor,
        actor_token_type: args.actor ? ACCESS_TOKEN : undefined,
        audience: args.audience,
      }),
      clientCert: args.clientCert ?? true,
    }),
  );
}

/** サービスの受け口を、トークンをつけて呼ぶ。clientCert が偽なら、証明書なしで呼ぶ。 */
async function callService(args: { service: string; token: string; clientCert?: boolean }) {
  return reply(
    await call(args.service, "/hop", {
      method: "POST",
      headers: { authorization: `Bearer ${args.token}` },
      clientCert: args.clientCert ?? true,
    }),
  );
}

/** 別の名前空間のサービスに、つながるかを試す。 */
async function reachOtherNamespace(args: { namespace: string; service: string }) {
  const port = args.service === "insurer-auth" || args.service === "sales-agent" ? 8443 : 9443;
  return new Promise((resolve) => {
    const req = request(
      `https://${args.service}.${args.namespace}.svc:${port}/hop`,
      { method: "POST", rejectUnauthorized: false, timeout: 3000 },
      (res) => resolve({ connected: true, status: res.statusCode }),
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ connected: false, error: e.message }));
    req.end();
  });
}

function reply(r: Reply) {
  let body: unknown = r.body;
  try {
    body = JSON.parse(r.body);
  } catch {
    // JSON でない応答は、そのまま返す
  }
  return { status: r.status, body };
}

async function whoami() {
  const pem = readFileSync(`${SVID_DIR}/svid.pem`, "utf8").split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----";
  const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ""), "base64");
  return { spiffeId: spiffeId(self), x5t: createHash("sha256").update(der).digest("base64url") };
}

const commands: Record<string, (args: never) => Promise<unknown>> = {
  "customer-token": customerToken,
  "call-sales-agent": callSalesAgent,
  "client-credentials": clientCredentials,
  exchange,
  "call-service": callService,
  "reach-other-namespace": reachOtherNamespace,
  whoami,
  decode: async (args: { token: string }) => decodeJwt(args.token),
};

const [command, raw] = process.argv.slice(2);
const run = commands[command ?? ""];
if (!run) {
  console.error(`コマンドがない: ${command}`);
  process.exit(2);
}
run(JSON.parse(raw ?? "{}") as never)
  .then((out) => console.log(JSON.stringify(out)))
  .catch((e: Error) => {
    console.log(JSON.stringify({ error: e.message }));
    process.exit(1);
  });
