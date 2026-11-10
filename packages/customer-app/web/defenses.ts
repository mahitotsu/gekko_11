// 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
// 画面の防御（G22、G23）のうち、vulnerable のサーバーで外したものを読む。
// secure の版は、このファイルを defenses.secure.ts で置き換えてまとめ、外す道を持たない（D-24）。
import type { Defenses } from "./defense-state.ts";

export async function loadDefenses(): Promise<Defenses> {
  const res = await fetch("/defenses");
  const off = res.ok ? (((await res.json()) as { off?: Record<string, string> }).off ?? {}) : {};
  // 防御を外せる複製であることと、今外している防御を、画面の帯に出す
  return { enabled: (id) => !(id in off), replica: { off: Object.keys(off).sort() } };
}
