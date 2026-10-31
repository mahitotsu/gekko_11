# 実装の構成と動かし方

このリポジトリの実装の技術スタック、フォルダ構成、動かし方、簡略化した点、まだ確かめていないことを示す。

**この文書の読み手:** 実装を読む人、動かす人、手を入れる人。Docker と Node.js を使え、Kubernetes の基本（Pod、名前空間）を知っている。Java と Python は手元に要らない。読んだ後に、どのフォルダに何があるかが分かり、クラスタを組み立ててテストを回せる。構成と標準仕様は[アーキテクチャ](architecture.md)、シナリオと再現手順は[シナリオ](scenarios.md)にある。

## 要旨
- **構成:** サービスごとに言語を選び、k3d の 1 つのクラスタの secure と vulnerable の名前空間で動かす（D-22）。保険会社のシステムと認可サーバーは Java、事務サービスは Python、それ以外は TypeScript である。
- **動かし方:** `npm test` が 3 つの言語の単体テストを回す。`npm run cluster:deploy` がクラスタを組み立て、`npm run cluster:test` が全シナリオを確かめる。
- **防御を外す受け口は、vulnerable のイメージだけにある:** 防御の ID ごとに、管理のポートで実行中に外す。教材のための意図的な実装で、本番の部品として使わない（D-24）。
- **営業 AI エージェント:** secure では、本物の Claude（既定は Haiku）で動く。vulnerable では台本で動く（D-23）。
- **まだ確かめていないこと:** 顧客のアプリの画面とブラウザの passkey、監査サービスと記録の集約（段 2 と段 3）。

## 1. 技術スタックは、サービスごとに選んだ言語と、k3d の基盤である
| 領域 | 使うもの | 使う場所 |
|---|---|---|
| 認可サーバー | Java 21、Spring Boot 3.5、Spring Authorization Server 1.5、webauthn4j | `services/insurer-auth` |
| 保険会社のシステム | Java 21、Spring Boot 3.5、nimbus-jose-jwt、java-json-canonicalization（JCS）、webauthn4j | `services/insurer-backend` |
| 事務サービス | Python 3.12、FastMCP 4.1、httpx2 | `services/insurer-mcp` |
| 営業 AI エージェント | TypeScript、Claude Agent SDK、MCP の SDK、Hono | `packages/sales-agent` |
| token-guard、顧客のアプリ | TypeScript、Hono、jose | `packages/token-guard`、`packages/customer-app` |
| クラスタと基盤 | k3d 5.9（k3s 1.35）、SPIRE 1.15、spiffe-helper 0.12、Envoy 1.31、NetworkPolicy | `deploy/` |
| テスト | JUnit、pytest、vitest | 各サービスの `test`、`test/cluster/` |

TypeScript は、Node.js 24 の型の取り除きで、そのまま動かす。Java と Python は、Docker の中でビルドし、テストする。部品を選んだ理由は、判断（D-16、D-19、D-22）にある。

## 2. フォルダ構成は、言語ごとのサービスと、クラスタの組み立てと、テストである
```text
services/
  insurer-auth/      認可サーバー（トークンの発行と交換、本人確認の属性、passkey の登録、失効、有効性の問い合わせ）
  insurer-backend/   保険会社のシステム（案の署名、申込みの検証、契約の記録、直送、監査の役への記録）
  insurer-mcp/       事務サービス（MCP の道具と、ツールの呼び出しの記録）
packages/
  sales-agent/       営業 AI エージェント（Claude Agent SDK。台本でも動く）
  customer-app/      顧客のアプリ（段 1 は、直送を受ける受け口と照合だけ）
  token-guard/       各 Pod で、Envoy から呼ばれ、トークンを確かめ、替える
deploy/              クラスタの構成（k3d、SPIRE）、マニフェストの生成、組み立てのスクリプト、Node のイメージ
test/cluster/        クラスタのシナリオのテストと、クラスタの中で役を演じる probe
scripts/             Java と Python の単体テストを Docker で回すスクリプト
```

主なファイルは、次のとおり。

| ファイル | 役割 |
|---|---|
| `services/insurer-auth/src/main/java/jp/gekko11/insurerauth/` | 認可サーバーの拡張点（SAN の照合、交換の前の確かめ、トークンの形、有効性の問い合わせ） |
| `services/insurer-backend/src/main/java/jp/gekko11/insurerbackend/ApplicationController.java` | 申込みの内容の確かめ（D9、D11〜D18） |
| `services/*/src/vulnerable/java/` | vulnerable のビルドだけに入る、防御を外す受け口 |
| `packages/token-guard/src/verify.ts` | 受け口の確かめ（D1、D5〜D8、D10、D20、D26、D27） |
| `packages/token-guard/src/exchange.ts` | 出口の交換（D2） |
| `packages/*/src/*.secure.ts` | secure のビルドで、防御を外す受け口と置き換えるファイル |
| `deploy/render.ts` | 名前空間ごとのマニフェスト（Envoy の設定、NetworkPolicy を含む） |
| `test/cluster/scenarios.test.ts`、`test/cluster/expiry.test.ts` | 23 のシナリオと補足のテスト |
| `test/cluster/probe/probe.ts` | クラスタの中で、顧客、乗っ取られた複製、攻撃者、運用の担当、監査の役を演じる |

## 3. ポートと環境変数は、マニフェストの生成で決まる
前提は、Docker（cgroup v2、BuildKit）、k3d、kubectl、Node.js 24 以上、npm 11 以上である。

```sh
npm install
npm test                 # 3 つの言語の単体テスト
npm run cluster:up       # k3d のクラスタを作る
npm run cluster:deploy   # SPIRE、イメージ、secure と vulnerable の名前空間を置く
npm run cluster:test     # 全シナリオ（20 分ほど）。期待する結果: 全て通る
npm run cluster:down     # クラスタを消す
```

営業 AI エージェントを secure で Claude として動かすには、`.env` に `CLAUDE_CODE_OAUTH_TOKEN` を置いてから `cluster:deploy` を回す。値は `claude setup-token` で取得する。値は secure の名前空間の Secret にだけ入り、`.env` は git に入れない。文書とコードに値を書かない。値がなければ、secure でも台本で動く。

| 動くもの | ポート | 主な環境変数 |
|---|---|---|
| 認可サーバー | 8443（TLS、証明書は任意） | `ISSUER`、`NAMESPACE`、`SVID_DIR`、`RP_ID`、`WEBAUTHN_ORIGINS` |
| 営業 AI エージェント、顧客のアプリの受け口（Envoy） | 8443（TLS、証明書なし） | — |
| 事務サービス、保険会社のシステム、直送の受け口（Envoy） | 9443（mTLS） | — |
| Envoy の出口 | 15101（認可サーバー）、15102（次の段）、15103（顧客のアプリ） | — |
| アプリ、token-guard | 8080、9100（Pod の中だけ） | `SERVICE`、`INGRESS_PROOF`、`ALLOWED_CALLERS`、`NEXT_SERVICE`、`CLAUDE_MODEL` |
| 管理のポート（vulnerable だけ） | 9090（token-guard）、9091（アプリ） | — |

イメージのビルドは、Maven、pip、npm の取り込みを BuildKit のキャッシュに置き、ビルドの間で使い回す。

## 4. 防御は、vulnerable の管理のポートで、防御の ID ごとに外す
vulnerable のイメージの token-guard、認可サーバー、保険会社のシステムは、管理のポートで `GET /defenses` と `PUT /defenses`（例: `{"off": {"D7": "off"}}`）を受ける。営業 AI エージェントは、`PUT /tamper` で、乗っ取られた AI の書き換えを入れる。切り替えはメモリ上で行い、Pod は入れ替えない。どの防御をどの部品が受けるかは、[シナリオ](scenarios.md)の 2-3 の表にある。

secure のイメージは、ビルドの時点で、この受け口を含まない。Java は Maven の profile、TypeScript はファイルの置き換えで分ける。事務サービスは、外す防御を token-guard に移したので、イメージは 1 つである。

## 5. 簡略化した点
- **業務の記憶と鍵は、メモリ上にある:** 認可サーバーと保険会社のシステムの記憶（passkey の登録、契約の記録、`nonce`）と、発行と提示の鍵は、起動ごとに作る。再起動で消える。
- **ログインは固定ユーザーである:** alice、bob、mallory が、パスワード `demo` で入れる。本人確認の記録は、認可サーバーに固定で持つ。
- **passkey の署名回数を見ない:** 同期される passkey は回数が 0 のままのため、重複は `nonce` で防ぐ。
- **確かめの役は、乗っ取られた複製として動く:** probe は、そのサービスの ServiceAccount で動き、同じ SPIFFE ID を持つ。別の SVID が要る役は、別のノードに置く（F-G53）。
- **上流への接続は、要求ごとにつなぎ直す:** SVID が入れ替わった後に、前の証明書の接続を使い回すと、新しい証明書に結んだトークンと食い違う。要求ごとに新しくつなぎ、そのときの SVID で示す（F-G54）。
- **`actor_token` は、替えるたびに取り直す:** SVID が入れ替わると、前の証明書に結んだ `actor_token` は使えないためである（F-G54）。
- **クラスタの入口はない:** 顧客の役は、クラスタの中の probe が演じる。ブラウザからの入口は、段 2 で置く。

## 6. まだ確かめていないこと
- 顧客のアプリの画面は、まだない。顧客の操作は、テストの中でソフトウェア認証器が行う。ブラウザの passkey（Windows Hello 等）と DPoP の鍵での動作は、実行して確かめていない。
- [シナリオ](scenarios.md)の防御のうち、次の 4 つは、再現するテストがない。
  - **画面とともに未実装:** 顧客のアプリが ID トークンを確かめる（D21）、案の署名を確かめてから示す（D22）、確認画面を署名する内容から作る（D23）。
  - **運用で行う:** 記録による監査（D25）。監査サービスと記録の集約は、段 3 で作る。
- 種類の違うトークンで鍵と `iss` を分けること（D3c の一部）は、未実装である。ID トークンとアクセストークンは、同じ鍵と `iss` で出す。
- secure の営業 AI エージェント（Claude）が、相談に応じて道具を呼ぶことは、基本の流れで確かめた。Claude の答え方そのものの良し悪しは、確かめていない。
