// 出口の替え（D-7 の替える段の手順）。認可サーバーへは、Envoy の出口が SVID で mTLS をかける。
import { config } from "./config.ts";
import { Refusal } from "./verify.ts";

const ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";

async function tokenRequest(params: Record<string, string>): Promise<string> {
  const res = await fetch(`${config.authUrl}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ client_id: config.service, ...params }),
  });
  const body = (await res.json().catch(() => ({}))) as { access_token?: string; error?: string; error_description?: string };
  if (!res.ok || !body.access_token) {
    throw new Refusal(403, `認可サーバーが拒否した: ${res.status} ${body.error ?? ""} ${body.error_description ?? ""}`);
  }
  return body.access_token;
}

/**
 * 出されたトークンを、次の段の宛先に替える。actor_token は、自分の証明書に結んだ自分のトークンである。
 * SVID が入れ替わると、前の証明書に結んだ actor_token は使えないので、替えるたびに取り直す。
 */
export async function exchangeForNext(subjectToken: string): Promise<string> {
  if (!config.next) throw new Refusal(403, "次の段がない");
  const actorToken = await tokenRequest({ grant_type: "client_credentials" });
  return tokenRequest({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN,
    actor_token: actorToken,
    actor_token_type: ACCESS_TOKEN,
    audience: config.next,
  });
}
