# gekko_11: 保険の窓口で学ぶ、AI が代理する取引の検証

AI エージェントが人の代わりに取引をするとき、その取引が確かなものかを、当事者の言い分だけでなく、第三者の情報と突き合わせて確かめる。その考え方を、保険の窓口の例えと、動く実装で見せる教材。

**読み手:** OAuth や passkey などの専門用語を知らない人。立場は問わない。[目的と題材の理由](docs/purpose.md)から読める。実装を読む人と動かす人は、下の表の 3 以降を読む。

## 読む順番
1 と 2 は、専門用語なしで読める。3 以降は、技術の言葉と標準仕様を使う。

| 順 | 知りたいこと | 読む文書 |
|---|---|---|
| 1 | 伝えたいこと（3 つの確認）、AI で難しくなること、例えと題材を選んだ理由 | [purpose.md](docs/purpose.md) |
| 2 | 保険の窓口が、3 つの確認をどう行っているか | [domain.md](docs/domain.md) |
| 3 | AI が営業員を担う構成で、3 つの確認をどう行うか。標準仕様と検証項目 | [architecture.md](docs/architecture.md) |
| 4 | 実装の技術スタック、フォルダ構成、動かし方 | [implementation.md](docs/implementation.md) |
| 5 | 確認を省いた実装と、確認する実装の比較（17 シナリオ） | [scenarios.md](docs/scenarios.md) |
| 随時 | 用語の意味 | [glossary.md](docs/glossary.md) |
| 付録 | 窓口の調査と設計の根拠、事実と出典 | [research/](docs/research/findings.md) |

## 動かして確かめる
前提: Node.js 24 以上、npm 11 以上。

```sh
npm install
npm test
```

期待する結果: `57 passed`。全シナリオで、悪い実装は攻撃を通し、良い実装は拒否する。サービスの起動と環境変数は、[implementation.md](docs/implementation.md) にある。
