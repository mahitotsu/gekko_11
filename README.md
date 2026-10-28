# gekko_11: 保険の窓口で学ぶ、JWT の検証

AI エージェントが間に入る多段呼び出しで、JWT（認可の票）を正しく検証し、正しく検証できる JWT を発行することの大切さを、保険の窓口の例えで見せる教材。

**読み手:** システムを発注する人、提案する人、受注して作る人。OAuth や JWT を知らなくても、[ストーリー](docs/story.md)から読める。読んだ後に、多段呼び出しの設計で何を確かめるべきかを、自分の言葉で説明できる。

## 答え
- **検証するのは票だけではない:** 票の署名・発行元・宛先・期限に加え、顧客が署名した申込の内容が変わっていないかを、署名の連鎖で確かめる。最後は、保険会社が AI を経由せずに契約内容を顧客へ直接送り、顧客が照合する。票だけでは、間にいる AI の書き換えを防げない。
- **票を使い回さない:** 窓口ごとに宛先を絞った票へ、保険会社の認可サーバーが発行し直す（token exchange）。利用者本人（`sub`）は残り、経由した営業員（AI）は `act` に残る。
- **発行側も同じだけ重要:** 宛先が広すぎる票や、取決めを広げられる回付は、受け取る側がどれだけ丁寧でも防げない。

## 読む順番
| 知りたいこと | 読む文書 |
|---|---|
| 保険の窓口の例えと、仕様の用語の対応 | [story.md](docs/story.md) |
| 発注・提案・要件定義で何を確かめるか | [for-buyers.md](docs/for-buyers.md) |
| 検証と発行のチェックリスト | [checklist.md](docs/checklist.md) |
| 悪い実装と良い実装の比較（17 シナリオ） | [scenarios.md](docs/scenarios.md) |
| 改ざん防止の方式の比較と限界 | [signing.md](docs/signing.md) |
| DX 前の営業窓口（保険の募集）の統制の調査 | [report.md](docs/research/report.md) |
| 営業窓口の統制を DX で同等以上にする設計 | [dx-design.md](docs/research/dx-design.md) |
| 営業窓口の調査の根拠となる事実と出典 | [findings.md](docs/research/findings.md) |
| 設計の判断と理由 | [design-decisions.md](docs/research/design-decisions.md) |
| 用語の意味 | [glossary.md](docs/research/glossary.md) |
| このリポジトリの出発点のメモ | [background.md](docs/background.md) |

## 最短の使い方
前提: Node.js 24 以上、npm 11 以上。

```sh
npm install
npm test
```

期待する結果: `57 passed`。全シナリオで、悪い実装は攻撃を通し、良い実装は拒否する。

サービスだけを起動するとき:

```sh
cp .env.example .env   # Claude を使うなら CLAUDE_CODE_OAUTH_TOKEN を貼る
npm run dev            # 5 つのサービスが起動する
```

顧客のアプリの画面は未実装である（次の回で作る）。今は、テストが顧客の操作を代行する。`.env` に `CLAUDE_CODE_OAUTH_TOKEN` がなければ、営業員は決まった台本で動く。値は `claude setup-token` で取得する。`.env` は git に入れない。

悪い実装は環境変数で選ぶ。`INSURER_MODE=bad`（全体）、`INSURER_MODE_BACKEND=bad` のようにサービス単位でも指定できる。細かい切り替えは [scenarios.md](docs/scenarios.md) にある。

## まだ確かめていないこと
- 本物の Claude（Agent SDK）での動作と、ブラウザのパスキー（Windows Hello 等）での署名は、実行して確かめていない。テストは台本の営業員とソフトウェア認証器で通っている。顧客のアプリの画面もない。
- 仕様の記述は、一次資料で本文を確認したものと、未確認のものがある。確認の状況は [dx-design.md](docs/research/dx-design.md) と [findings.md](docs/research/findings.md) にある。

## 持ち主と、更新のきっかけ
- **持ち主:** このリポジトリの作者（akring）。
- **更新のきっかけ:** `packages/insurer-backend/src/` の検証項目を変えたら [checklist.md](docs/checklist.md) と [scenarios.md](docs/scenarios.md) を直す。シナリオを足したら `test/scenarios.test.ts` と [scenarios.md](docs/scenarios.md) を同じ変更で直す。
