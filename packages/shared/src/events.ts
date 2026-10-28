import { urls } from "./config.js";

// 可視化パネルに出すイベント。各窓口が何を受け取り、何を照合したか。
export interface CheckResult {
  name: string; // 例: "aud が自分宛て"
  ok: boolean;
  detail?: string;
}
export interface InsurerEvent {
  at: number;
  actor: string; // どの窓口か(例: "insurer-backend")
  mode: "good" | "bad";
  action: string; // 例: "申込みを受付"
  ticket?: { sub?: string; aud?: unknown; act?: string[]; scope?: string; exp?: number };
  checks: CheckResult[];
  outcome: "ok" | "rejected";
}

export async function emit(e: Omit<InsurerEvent, "at">): Promise<void> {
  const full = { at: Date.now(), ...e };
  console.log(`[${e.actor}/${e.mode}] ${e.action} → ${e.outcome}`, e.checks.filter((c) => !c.ok).map((c) => c.name));
  try {
    await fetch(`${urls.customerApp}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(full),
    });
  } catch {
    // 可視化は付加機能。画面が無くても動かす。
  }
}
