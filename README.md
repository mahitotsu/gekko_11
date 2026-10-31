# gekko_11: 保険の窓口で学ぶ、AI が代理する取引の検証

AI エージェントが人の代わりに取引をするとき、その取引が確かなものかを、当事者の言い分だけでなく、第三者の情報と突き合わせて確かめる。その考え方を、保険の窓口の例えと、動く実装で見せる教材。

**読み手:** OAuth や passkey などの専門用語を知らない人。立場は問わない。[AI に取引を任せるときに、確かめるべきこと](docs/purpose.md)から読める。実装を読む人と動かす人は、下の表の 2 以降を読む。

## 読む順番
1 は、専門用語なしで読める。2 以降は、技術の言葉と標準仕様を使う。

| 順 | 知りたいこと | 読む文書 |
|---|---|---|
| 1 | AI に取引を任せるとき、何を確かめるべきか。なぜ抜けやすいか | [AI に取引を任せるときに、確かめるべきこと](docs/purpose.md) |
| 2 | AI を使う構成は、どんな全体像で動き、確かめるべきことをどう満たすか。どの標準仕様に準拠するか | [アーキテクチャ](docs/architecture.md) |
| 3 | 実装はどう作られ、どう動かすか | [実装の構成と動かし方](docs/implementation.md) |
| 4 | 確認を省くと、何が起きるか。どう再現するか | [確認を省いたときのシナリオ](docs/scenarios.md) |
| 随時 | 言葉の意味は何か | [用語集](docs/glossary.md) |
| 付録 | 主張の根拠は何か（AI エージェント向け） | [ナレッジの索引と使い方](docs/knowledge/README.md) |

## 動かして確かめる
前提: Docker（cgroup v2）、k3d、kubectl、Node.js 24 以上、npm 11 以上。Java と Python は、Docker の中で使う。

```sh
npm install
npm test                 # サービスごとの単体テスト（TypeScript、Java、Python）
npm run cluster:up       # k3d のクラスタを作る
npm run cluster:deploy   # secure と vulnerable の名前空間に、全てのサービスを置く
npm run cluster:test     # 全シナリオを確かめる（20 分ほど）
```

期待する結果: どちらのテストも、全て通る。防御を外した vulnerable の名前空間では被害が出て、secure の名前空間では出ない。クラスタの構成と環境変数、Claude の認証情報の置き方は、[implementation.md](docs/implementation.md) にある。
