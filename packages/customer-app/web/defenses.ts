// 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
// 画面の防御（D21〜D23）のうち、vulnerable のサーバーで外したものを読む。
// secure の版は、このファイルを defenses.secure.ts で置き換えてまとめ、外す道を持たない（D-24）。
export async function loadDefenses(): Promise<(id: string) => boolean> {
  const res = await fetch("/defenses");
  const off = res.ok ? (((await res.json()) as { off?: Record<string, string> }).off ?? {}) : {};
  return (id) => !(id in off);
}
