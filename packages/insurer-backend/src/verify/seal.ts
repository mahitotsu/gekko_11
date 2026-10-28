// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from "@simplewebauthn/server";
import { compactVerify, importJWK } from "jose";
import { INTERNAL_KEY, agentKey, canonical, challengeOf, urls, type Application } from "@gekko/shared";

const RP_ID = "localhost";

export interface SealResult { ok: boolean; detail: string }
export interface SealInput {
  content: unknown; // 署名の対象(意向確認、または申込み)
  assertion: unknown; // passkey: WebAuthn assertion / agent-signed: 営業員が付けた JWS
  user: string;
  peer?: string; // mtls-only: 通信相手の識別(リバースプロキシが mTLS で認証した結果を想定)
}

// 署名は2つのことを同時に示す。
//   誰が承認したか: 本人(user)が登録したパスキーで署名されている
//   何を承認したか: 署名が内容のハッシュ(challenge)に結び付いている
// 同期されるパスキーは署名回数(counter)が 0 のままなので、counter では重複を見ない。重複は nonce で防ぐ。
export async function verifyPasskey({ content, assertion, user }: SealInput): Promise<SealResult> {
  const a = assertion as AuthenticationResponseJSON | undefined;
  if (!a?.id) return { ok: false, detail: "署名(assertion)がありません" };
  const res = await fetch(`${urls.insurerAuth}/internal/passkeys/${user}`, { headers: { "x-internal-key": INTERNAL_KEY } });
  const list = (await res.json()) as { id: string; publicKey: string }[];
  const key = list.find((k) => k.id === a.id);
  if (!key) return { ok: false, detail: `${user} が登録したパスキーの署名ではありません` };
  try {
    const v = await verifyAuthenticationResponse({
      response: a,
      expectedChallenge: challengeOf(content), // 内容のハッシュ。内容が1文字でも変われば一致しない
      expectedOrigin: urls.customerApp, // 署名したのは顧客のアプリの画面であること
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: { id: key.id, publicKey: Buffer.from(key.publicKey, "base64url"), counter: 0 },
    });
    return v.verified ? { ok: true, detail: "内容は署名時のままです" } : { ok: false, detail: "署名が内容と一致しません" };
  } catch (e) {
    const m = (e as Error).message;
    return { ok: false, detail: /challenge/i.test(m) ? "署名が内容と一致しません(内容が署名時と違います)" : `署名の検証に失敗: ${m}` };
  }
}

// 不十分な例1: 通信相手(MCP)が信頼できるなら、運ばれてきた中身も信じる。
// 実際の mTLS は TLS 終端で相手を認証するだけ。ここでは終端した結果が peer に入る想定で再現する。
export async function verifyMtlsOnly({ peer }: SealInput): Promise<SealResult> {
  return peer === "insurer-mcp"
    ? { ok: true, detail: "信頼する MCP(mTLS)から届いたので受け付けます(中身は見ていません)" }
    : { ok: false, detail: "信頼する MCP からの通信ではありません" };
}

// 不十分な例2: 営業員(AI)が申込みに署名しているので正しいとみなす。
// 署名したのは書き換えた張本人かもしれない、という点を見ていない。
export async function verifyAgentSigned({ content, assertion }: SealInput): Promise<SealResult> {
  try {
    const { payload } = await compactVerify(String(assertion), await importJWK(agentKey.pub, "ES256"));
    return new TextDecoder().decode(payload) === canonical(content as Application)
      ? { ok: true, detail: "営業員の署名と申込みが一致しました(誰の意思かは見ていません)" }
      : { ok: false, detail: "営業員の署名と申込みが一致しません" };
  } catch {
    return { ok: false, detail: "営業員の署名が不正です" };
  }
}

export const verifyNone = async (): Promise<SealResult> => ({ ok: true, detail: "署名を確認していません" });
