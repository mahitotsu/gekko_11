// base64url と SHA-256 と、署名する内容の challenge（JCS で正規化した内容の SHA-256。D-1）。ブラウザと Node の両方で動く。
import canonicalize from "canonicalize";

export const b64u = (bytes: ArrayBuffer | Uint8Array): string => {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const fromB64u = (text: string): Uint8Array<ArrayBuffer> => {
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
};

export const randomB64u = (n = 32): string => b64u(crypto.getRandomValues(new Uint8Array(n)));

export const sha256 = async (text: string): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

/** JCS（RFC 8785）で正規化した内容の SHA-256 の base64url。passkey に署名させる challenge で、提示集合の識別子にも使う。 */
export async function challengeOf(value: unknown): Promise<string> {
  const c = canonicalize(value);
  if (!c) throw new Error("正規化できない");
  return b64u(await sha256(c));
}
