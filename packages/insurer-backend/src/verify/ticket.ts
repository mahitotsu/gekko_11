// 教材のための意図的に悪い実装を含む。本番の部品として使わないこと。
import { audiences, verifyTicketWith, type Ticket } from "@gekko/shared";
import type { TicketCheck } from "../config.js";

const base = { signature: true, audience: audiences.backend, expiry: true, typ: true };

// トークンの検証。check を変えると何を省くかが変わる。
export function verifyTicket(token: string, check: TicketCheck): Promise<Ticket> {
  switch (check) {
    case "good": return verifyTicketWith(token, base);
    case "no-aud": return verifyTicketWith(token, { ...base, audience: undefined });
    case "no-exp": return verifyTicketWith(token, { ...base, expiry: false });
    case "no-typ": return verifyTicketWith(token, { ...base, typ: false });
    case "no-signature": return verifyTicketWith(token, { ...base, signature: false });
    case "signature-only": return verifyTicketWith(token, { signature: true, expiry: false, typ: false });
  }
}

// 画面に出す「何を確かめたか」の一覧。
export function ticketChecklist(check: TicketCheck) {
  return [
    { name: "署名が保険会社のものと一致する", on: check !== "no-signature" },
    { name: "宛先(aud)が事務センターである", on: check === "good" || check === "no-exp" || check === "no-typ" },
    { name: "期限内である", on: check === "good" || check === "no-aud" || check === "no-typ" },
    { name: "トークンの種類(typ)がアクセス用である", on: check === "good" || check === "no-aud" || check === "no-exp" },
  ];
}
