// サイトの数字（src/data/facts.ts）が、正本の docs と一致するかを照らす（CLAUDE.md の「site/」）。
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { counts } from "../src/data/facts.ts";

const read = (path: string) => readFileSync(new URL(`../../docs/${path}`, import.meta.url), "utf8");

test("scenarios の見出しの、リスク、手口、防御、シナリオの数と一致する", () => {
  const md = read("scenarios.md");
  const head = /^## 2\. リスクは (\d+)、手口は (\d+)、防御は (\d+)/m.exec(md);
  assert.ok(head, "scenarios.md の 2 章の見出しが読めない");
  assert.deepEqual([Number(head[1]), Number(head[2]), Number(head[3])], [counts.risks, counts.attacks, counts.defenses]);
  const scenarios = /^## 3\. (\d+) のシナリオ/m.exec(md);
  assert.equal(Number(scenarios?.[1]), counts.scenarios);
});

test("architecture の要件の数と一致する", () => {
  const md = read("architecture.md");
  const head = /^### 1-2\. 要件: .*?(\d+) 件/m.exec(md);
  assert.equal(Number(head?.[1]), counts.requirements);
  const rows = md.split("\n").filter((l) => /^\| \d+\. /.test(l));
  assert.equal(rows.length, counts.requirements);
});
