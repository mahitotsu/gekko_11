// 章とページの並び。見出しは、そのページの主張である。前へ／次へと、章の中の位置は、ここから組む。
export interface Page {
  path: string;
  title: string;
}

export interface Chapter {
  id: "business" | "architecture" | "technology";
  name: string;
  /** なぜ・どうやって・何で */
  question: string;
  reader: string;
  summary: string;
  pages: Page[];
}

export const chapters: Chapter[] = [
  {
    id: "business",
    name: "ビジネス",
    question: "なぜ",
    reader: "発注、企画、事業の責任者へ",
    summary: "AI エージェントに取引を任せても守れることと、要件として求めること",
    pages: [
      { path: "business/1/", title: "AI に任せる取引は、営業員を介した保険の窓口と同じ形をしている" },
      { path: "business/2/", title: "AI が乗っ取られても、本人が署名した内容以外は契約にならない" },
      { path: "business/3/", title: "誰が何に同意したかを、署名と記録で後から示せる" },
      { path: "business/4/", title: "監査では、AI の言い分ではなく、第三者の記録と突き合わせる" },
      { path: "business/5/", title: "確認は、要件として求めないと抜ける" },
    ],
  },
  {
    id: "architecture",
    name: "アーキテクチャ",
    question: "どうやって",
    reader: "設計をする人へ",
    summary: "AI に鍵も記録も持たせず、確かめる役を分ける設計",
    pages: [
      { path: "architecture/1/", title: "AI には、鍵も記録も持たせない" },
      { path: "architecture/2/", title: "証明と署名を出す者、運ぶ者、確かめる者を分ける" },
      { path: "architecture/3/", title: "標準に従い、標準で決まらない組み方だけを自分で決める" },
      { path: "architecture/4/", title: "書き換えは、署名と直送と突き合わせの 3 段で見つける" },
      { path: "architecture/5/", title: "監査の記録は、書き手を確かめて集め、書いた者には書き換えさせない" },
    ],
  },
  {
    id: "technology",
    name: "テクノロジー",
    question: "何で",
    reader: "実装する人、確かめる人へ",
    summary: "標準と部品が塞ぐ抜けと、手元での再現",
    pages: [
      { path: "technology/1/", title: "技術ごとに、塞ぐ抜けが決まっている" },
      { path: "technology/2/", title: "トークンは、渡る先ごとに替え、本人と経由を最後まで届ける" },
      { path: "technology/3/", title: "盗まれたトークンは、鍵がなければ使えない" },
      { path: "technology/4/", title: "本人の同意を、内容そのものに結ぶ" },
      { path: "technology/5/", title: "AI とのやりとりでは、AI の言葉と、署名された内容を分けて運ぶ" },
      { path: "technology/6/", title: "全てのシナリオを、手元のクラスタで再現できる" },
    ],
  },
];

/** ページの章と位置、前後のページ。 */
export function locate(path: string) {
  const all = chapters.flatMap((c) => c.pages.map((p, i) => ({ chapter: c, page: p, index: i })));
  const at = all.findIndex((x) => x.page.path === path);
  if (at < 0) throw new Error(`pages.ts にないページ: ${path}`);
  return { ...all[at]!, prev: all[at - 1]?.page, next: all[at + 1]?.page };
}
