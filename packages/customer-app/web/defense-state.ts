// 画面の防御の状態の型。secure と vulnerable の両方の版（defenses.ts、defenses.secure.ts）が使う。
export interface Defenses {
  enabled: (id: string) => boolean;
  /** 防御を外せる複製（vulnerable）だけが持つ。今外している防御の ID。 */
  replica?: { off: string[] };
}
