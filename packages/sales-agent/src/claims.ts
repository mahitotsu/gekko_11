// token-guard が確かめた主張（x-auth-claims）。アプリは、トークンも証明書も持たず、この主張だけを使う（architecture の 2-2）。
export interface Terms {
  type: string;
  kinds: string[];
  maxBenefit: number;
}

export interface Claims {
  sub: string;
  authorization_details?: Terms[];
  [name: string]: unknown;
}

export function claimsOf(header: string | undefined): Claims {
  if (!header) throw new Error("確かめた主張がない");
  return (JSON.parse(Buffer.from(header, "base64url").toString()) as { claims: Claims }).claims;
}
