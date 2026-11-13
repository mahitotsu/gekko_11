// サイトに出す数字と呼び名（CLAUDE.md の「site/」）。正本は docs で、ここの値は docs と照らすテストがある（site/test/facts.test.ts）。
export const REPO = "https://github.com/mahitotsu/gekko_11";

/** docs の文書への GitHub のリンク。 */
export const doc = (path: string) => `${REPO}/blob/main/docs/${path}`;

export const counts = {
  /** architecture 1-2 の要件の数 */
  requirements: 12,
  /** scenarios 2 章のリスク、手口、防御の数 */
  risks: 10,
  attacks: 23,
  defenses: 37,
  /** scenarios 3 章のシナリオの数 */
  scenarios: 27,
};
