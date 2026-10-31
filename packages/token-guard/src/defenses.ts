// 教材のための意図的に悪い実装を含む（vulnerable の名前空間だけで使う）。本番の部品として使わないこと。
// 防御を 1 つずつ外せる。secure の版は、このファイルを defenses.secure.ts で置き換えてビルドし、切り替えの受け口を持たない（D-20）。
const off = new Set((process.env.DEFENSES_OFF ?? "").split(",").filter(Boolean));

/** D26: トークンの送信者の鍵への結び付けを確かめる。D27: 呼ぶ相手の SPIFFE ID を確かめる。 */
export const enabled = (defense: "D26" | "D27"): boolean => !off.has(defense);
