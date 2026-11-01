import { describe, expect, it } from "vitest";
import { markdownToHtml } from "../web/markdown.ts";

describe("営業 AI エージェントの説明文の表示", () => {
  it("表、箇条書き、太字、段落を整える", () => {
    const html = markdownToHtml("案は2つです。\n\n| 案 | 月額 |\n|---|---|\n| 確定 | 2万円 |\n\n- **確定年金**は10年");
    expect(html).toBe(
      "<p>案は2つです。</p><table><thead><tr><th>案</th><th>月額</th></tr></thead><tbody><tr><td>確定</td><td>2万円</td></tr></tbody></table>" +
        "<ul><li><strong>確定年金</strong>は10年</li></ul>",
    );
  });

  it("説明文に紛れた HTML は、文字として表示する", () => {
    expect(markdownToHtml('<img src=x onerror="alert(1)">')).toBe("<p>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</p>");
  });
});
