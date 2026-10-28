import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

// JCS(RFC 8785)で正規化する。キー順や空白の違いで署名が変わらないようにする。
export function canonical(value: unknown): string {
  const c = canonicalize(value);
  if (!c) throw new Error("cannot canonicalize");
  return c;
}

// パスキーに署名させる challenge。内容そのものに結び付く。
export function challengeOf(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("base64url");
}
