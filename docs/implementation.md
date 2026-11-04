# 実装の構成と動かし方

このリポジトリの実装の技術スタック、フォルダ構成、動かし方、簡略化した点、まだ確かめていないことを示す。

**この文書の読み手:** 実装を読む人、動かす人、手を入れる人。Docker と Node.js を使え、Kubernetes の基本（Pod、名前空間）を知っている。Java と Python は手元に要らない。読んだ後に、どのフォルダに何があるかが分かり、クラスタを組み立ててテストを回せる。構成と標準仕様は[アーキテクチャ](architecture.md)、シナリオと再現手順は[シナリオ](scenarios.md)にある。

## 要旨
- **構成:** サービスごとに言語を選び、k3d の 1 つのクラスタの secure と vulnerable の名前空間で動かす（D-22）。保険会社のシステム、認可サーバー、監査サービスは Java、事務サービスは Python、それ以外は TypeScript である。監査の記録は、Alloy が名前空間ごとの Loki に集める（D-30）。
- **動かし方:** `npm test` が 3 つの言語の単体テストを回す。`npm run cluster:deploy` がクラスタを組み立て、`npm run cluster:test` が全シナリオと画面のテストを確かめる。画面は、ブラウザで `http://app.secure.localhost:8081` を開いて使う。監査の画面は `http://audit.secure.localhost:8081` である。
- **防御を外す受け口は、vulnerable のイメージだけにある:** 防御の ID ごとに、管理のポートで実行中に外す。教材のための意図的な実装で、本番の部品として使わない（D-24）。
- **営業 AI エージェント:** 顧客と AG-UI 1.0 で会話する（D-29）。secure では本物の Claude（既定は Haiku）、vulnerable では台本で動く（D-23）。
- **まだ確かめていないこと:** passkey は、Windows Hello と VS Code に内蔵されたブラウザの組み合わせでだけ確かめた。記録が 7 日で消えることは、確かめていない。

## 1. 技術スタックは、サービスごとに選んだ言語と、k3d の基盤である
| 領域 | 使うもの | 使う場所 |
|---|---|---|
| 認可サーバー | Java 21、Spring Boot 3.5、Spring Authorization Server 1.5、webauthn4j | `services/insurer-auth` |
| 保険会社のシステム | Java 21、Spring Boot 3.5、nimbus-jose-jwt、java-json-canonicalization（JCS）、webauthn4j | `services/insurer-backend` |
| 事務サービス | Python 3.12、FastMCP 4.1、httpx2 | `services/insurer-mcp` |
| 監査サービス | Java 21、Spring Boot 3.5、Spring Security の OAuth2 Client 6.5、Thymeleaf、java-json-canonicalization（JCS） | `services/insurer-audit` |
| 営業 AI エージェント | TypeScript、Claude Agent SDK 0.3.302、@ag-ui/core 1.0.3（AG-UI の型と確かめ）、MCP の SDK、Hono | `packages/sales-agent` |
| token-guard | TypeScript、Hono、jose | `packages/token-guard` |
| 顧客のアプリ | TypeScript、jose、canonicalize（JCS）、@ag-ui/core（型だけ）、WebCrypto、WebAuthn。画面は esbuild 0.28 でまとめ、配信元は Hono | `packages/customer-app` |
| クラスタと基盤 | k3d 5.9（k3s 1.35）、SPIRE 1.15、spiffe-helper 0.12、Envoy 1.31、NetworkPolicy | `deploy/` |
| 記録の集約 | Grafana Alloy 1.20（`loki.source.kubernetes`）、Grafana Loki 3.7 | `deploy/k8s/logging/`、`deploy/render.ts` |
| テスト | JUnit、pytest、vitest、Playwright 1.64（Docker のブラウザに playwright-core でつなぐ） | 各サービスの `test`、`test/cluster/`、`test/ui/` |

TypeScript は、Node.js 24 の型の取り除きで、そのまま動かす。Java と Python は、Docker の中でビルドし、テストする。部品を選んだ理由は、判断（D-16、D-19、D-22、D-30、D-31）にある。

## 2. フォルダ構成は、言語ごとのサービスと、クラスタの組み立てと、テストである
```text
services/
  insurer-auth/      認可サーバー（トークンの発行と交換、本人確認の属性、passkey の登録、失効、有効性の問い合わせ）
  insurer-backend/   保険会社のシステム（案の署名、申込みの検証、契約の記録、直送、監査の役への記録）
  insurer-mcp/       事務サービス（MCP の道具と、ツールの呼び出しの記録）
  insurer-audit/     監査サービス（監査の担当のログイン、記録の読み手、突き合わせ、監査の画面）
packages/
  sales-agent/       営業 AI エージェント（AG-UI の受け口、Claude Agent SDK。台本でも動く）
  customer-app/      顧客のアプリ（web/ が画面、src/ が配信元と受信箱と照合）
  token-guard/       各 Pod で、Envoy から呼ばれ、トークンを確かめ、替える
deploy/              クラスタの構成（k3d、SPIRE、記録の集約）、マニフェストの生成（入口と Loki を含む）、組み立てのスクリプト、Node のイメージ
test/cluster/        クラスタのシナリオのテストと、クラスタの中で役を演じる probe
test/ui/             画面のテスト（Docker の Playwright のブラウザにつなぐ）
scripts/             Java と Python の単体テストを Docker で回すスクリプト
```

主なファイルは、次のとおり。

| ファイル | 役割 |
|---|---|
| `services/insurer-auth/src/main/java/jp/gekko11/insurerauth/` | 認可サーバーの拡張点（SAN の照合、交換の前の確かめ、トークンの形、有効性の問い合わせ） |
| `services/insurer-backend/src/main/java/jp/gekko11/insurerbackend/ApplicationController.java` | 申込みの内容の確かめ（D9、D11〜D18） |
| `services/*/src/vulnerable/java/` | vulnerable のビルドだけに入る、防御を外す受け口 |
| `services/insurer-audit/src/main/java/jp/gekko11/insureraudit/Reconciler.java` | 契約ごとの突き合わせ（D25）。書いた者を Pod の印で決める（D-32）。比べた値と書いた者を、根拠の強さごとにまとめて、画面と JSON に渡す |
| `services/insurer-audit/src/main/java/jp/gekko11/insureraudit/ClusterRecords.java` | Loki の問い合わせと、保険会社のシステムの自己申告（`/audit/records`）の読み手 |
| `services/insurer-audit/src/main/java/jp/gekko11/insureraudit/SecurityConfig.java` | 監査の担当のログイン（D-31） |
| `deploy/k8s/logging/alloy.yaml` | Alloy の設定。名前空間ごとに、監査の記録だけをその名前空間の Loki へ送る |
| `packages/token-guard/src/verify.ts` | 受け口の確かめ（D1、D5〜D8、D10、D20、D26、D27） |
| `packages/token-guard/src/exchange.ts` | 出口の交換（D2） |
| `packages/customer-app/web/checks.ts` | 画面の確かめ（D21〜D23） |
| `packages/customer-app/web/main.ts` | 画面の流れ（ログイン、登録、相談、確認、署名、照合） |
| `packages/sales-agent/src/agui.ts` | AG-UI の受け口（`POST /agui`。RunAgentInput を確かめ、SSE でイベントを返す） |
| `packages/sales-agent/src/thread.ts` | 会話ごとの状態と、画面側の道具の呼び出しと待ち合わせ（D-29）。会話の記録を、秘密を伏せて書き出す（D-32） |
| `packages/sales-agent/src/claude.ts`、`scripted.ts` | Claude と台本。同じ道具を呼ぶ |
| `packages/sales-agent/src/draft.ts`、`submit.ts` | 書類の組み立てと、署名の揃った書類の提出（D-27） |
| `packages/customer-app/web/agui.ts` | 画面の側の AG-UI の受け手と、画面側の道具の定義 |
| `packages/*/src/*.secure.ts`、`packages/customer-app/web/defenses.secure.ts` | secure のビルドで、防御を外す受け口と置き換えるファイル |
| `deploy/render.ts` | 名前空間ごとのマニフェスト（Envoy の設定、NetworkPolicy を含む） |
| `test/cluster/scenarios.test.ts`、`test/cluster/expiry.test.ts` | probe で確かめるシナリオと補足のテスト |
| `test/ui/scenarios.test.ts`、`test/ui/flow.test.ts` | 画面のシナリオ（8、24）、D21 の補足、画面の基本の流れ |
| `test/cluster/probe/probe.ts` | クラスタの中で、顧客、乗っ取られた複製、攻撃者、運用の担当、監査の役、監査の担当を演じる |

## 3. ポートと環境変数は、マニフェストの生成で決まる
前提は、Docker（cgroup v2、BuildKit）、k3d、kubectl、Node.js 24 以上、npm 11 以上である。

```sh
npm install
npm test                 # 3 つの言語の単体テスト
npm run cluster:up       # k3d のクラスタを作る
npm run cluster:deploy   # SPIRE、イメージ、secure と vulnerable の名前空間を置く
npm run cluster:test     # 全シナリオと画面のテスト（25 分ほど）。期待する結果: 全て通る
npm run cluster:down     # クラスタを消す
```

営業 AI エージェントを secure で Claude として動かすには、`.env` に `CLAUDE_CODE_OAUTH_TOKEN` を置いてから `cluster:deploy` を回す。値は `claude setup-token` で取得する。値は secure の名前空間の Secret にだけ入り、`.env` は git に入れない。文書とコードに値を書かない。値がなければ、secure でも台本で動く。

ブラウザは、入口を通って、名前空間ごとに次の名前に届く。secure はポート 8081、vulnerable は 8082 である。k3d の loadbalancer が、入口の NodePort（30081、30082）につなぐ。

| 名前 | 届く先 |
|---|---|
| `app.<名前空間>.localhost` | 顧客のアプリの配信元（画面、設定、提示の公開鍵、受信箱） |
| `auth.<名前空間>.localhost` | 認可サーバー（ブラウザに出す経路だけ）。issuer も、この名前である |
| `agent.<名前空間>.localhost` | 営業 AI エージェント（AG-UI の受け口 `POST /agui`） |
| `audit.<名前空間>.localhost` | 監査サービス（監査の画面と、同じ中身の JSON の受け口 `/api/contracts`） |

| 動くもの | ポート | 主な環境変数 |
|---|---|---|
| 認可サーバー | 8443（TLS、証明書は任意） | `ISSUER`、`NAMESPACE`、`SVID_DIR`、`RP_ID`、`WEBAUTHN_ORIGINS`、`CUSTOMER_REDIRECT_URI`、`AUDIT_REDIRECT_URI` |
| 営業 AI エージェント、顧客のアプリ、監査サービスの受け口（Envoy） | 8443（TLS、証明書なし） | — |
| 事務サービス、保険会社のシステム、直送の受け口（Envoy） | 9443（mTLS） | — |
| 入口（Envoy） | 8080（Pod の中）、NodePort 30081 と 30082 | — |
| Envoy の出口 | 15101（認可サーバー）、15102（次の段）、15103（顧客のアプリ）、15104（顧客のアプリから、保険会社のシステムの提示の公開鍵） | — |
| アプリ、token-guard | 8080、9100（Pod の中だけ） | `SERVICE`、`INGRESS_PROOF`、`PUBLIC_ORIGIN`、`ALLOWED_CALLERS`、`NEXT_SERVICE`、`CLAUDE_MODEL`、顧客のアプリは `ISSUER`、`RP_ID`、`APP_ORIGIN`、`AGENT_ORIGIN`、監査サービスは `ISSUER`、`PUBLIC_ORIGIN`、`LOKI_URL` |
| Loki | 3100（名前空間の中の HTTP。Alloy と監査サービスだけが届く） | — |
| 管理のポート（vulnerable だけ） | 9090（token-guard）、9091（アプリ） | — |

イメージのビルドは、Maven、pip、npm の取り込みを BuildKit のキャッシュに置き、ビルドの間で使い回す。

## 4. 防御は、vulnerable の管理のポートで、防御の ID ごとに外す
vulnerable のイメージの token-guard、認可サーバー、保険会社のシステム、顧客のアプリの配信元は、管理のポートで `GET /defenses` と `PUT /defenses`（例: `{"off": {"D7": "off"}}`）を受ける。顧客のアプリの画面は、開くときに配信元の `/defenses` を読み、外された D21〜D23 を飛ばす。営業 AI エージェントは、`PUT /tamper` で、乗っ取られた AI の書き換えを入れる。`PUT /forge-audit` は、本文をそのまま監査の記録として書き、ほかのサービスを名乗る記録の偽装を再現する。切り替えはメモリ上で行い、Pod は入れ替えない。どの防御をどの部品が受けるかは、[シナリオ](scenarios.md)の 2-3 の表にある。

secure のイメージは、ビルドの時点で、この受け口を含まない。Java は Maven の profile、TypeScript はファイルの置き換えで分ける。画面は、置き換えた後にまとめるので、secure の画面は外す道を持たない。事務サービスは、外す防御を token-guard に移したので、イメージは 1 つである。

## 5. 簡略化した点
- **業務の記憶と鍵は、メモリ上にある:** 認可サーバーと保険会社のシステムの記憶（passkey の登録、契約の記録、`nonce`）と、発行と提示の鍵は、起動ごとに作る。再起動で消える。認可サーバーが登録を忘れた後は、顧客のアプリが、ログインの直後に本人の passkey の一覧（`/passkeys/mine`）と照らして気付き、登録し直しに案内する。
- **ログインは固定ユーザーである:** 顧客の alice、bob、mallory、hanako と、監査の担当の kansa が、パスワード `demo` で入れる。本人確認の記録は、認可サーバーに固定で持つ。alice、bob、mallory はテストが使う。手で画面を試すときは hanako を使う。テストの申込みが、受信箱に混ざらないためである。監査の画面は、kansa で見る。
- **passkey の署名回数を見ない:** 同期される passkey は回数が 0 のままのため、重複は `nonce` で防ぐ。
- **確かめの役は、乗っ取られた複製として動く:** probe は、そのサービスの ServiceAccount で動き、同じ SPIFFE ID を持つ。別の SVID が要る役は、別のノードに置く（F-G53）。
- **上流への接続は、要求ごとにつなぎ直す:** SVID が入れ替わった後に、前の証明書の接続を使い回すと、新しい証明書に結んだトークンと食い違う。要求ごとに新しくつなぎ、そのときの SVID で示す（F-G54）。
- **`actor_token` は、替えるたびに取り直す:** SVID が入れ替わると、前の証明書に結んだ `actor_token` は使えないためである（F-G54）。
- **入口は、TLS なしの localhost である:** ブラウザと入口の間は、利用者の端末の中のループバックで、http で受ける。ブラウザは localhost を安全な文脈として扱うので、passkey と WebCrypto が動く（F-G62、F-G63）。本番では、信頼された証明書の HTTPS にする。issuer も http になる。
- **受信箱の番号は、端末の保存領域にある:** 番号を持つ者は、その受信箱を読める（D-26）。署名済み申込の写しも、同じ保存領域に置く。
- **会話の状態は、営業 AI エージェントのメモリにある:** threadId ごとの会話（Claude の会話、直前の提示、署名した書類）を、1 つの複製のメモリに持つ。再起動で消え、15 分使われなければ捨てる。トークン A は 5 分で切れるので、会話はその間に終える。
- **記録の集約は、教材の規模である:** Loki は、名前空間ごとに 1 つのプロセスで動き、認証を持たない。記録は、Pod の一時的な領域（emptyDir）のファイルに保存する。Pod を作り直すと、記録は消える。Alloy も 1 つで、止まっている間の記録は届かない。
- **監査は、AI への指示とモデルの変更を見ない:** 会話の記録に、動いたモデルの名前だけを残す。指示（プロンプト）の変更の記録と、その監査は作っていない。
- **probe の顧客の役も残る:** 多くのシナリオは、クラスタの中の probe が顧客を演じる。署名と DPoP の proof には、入口の公開名を使う。

## 6. まだ確かめていないこと
- 画面は、Chromium と仮想の認証器で自動テストした。さらに、Windows の VS Code に内蔵されたブラウザと Windows Hello で、ログインから照合まで手で確かめた（F-G63）。ほかのブラウザ（Chrome、Edge、Safari、Firefox）と、ほかの認証器（スマートフォンの passkey など）では、確かめていない。
- 顧客のアプリは、保険会社が署名した登録情報から、営業 AI エージェントの名称、所属、扱える範囲を示す（P-12）。この表示は、未実装である。画面は、取決めの範囲だけを示す。
- Loki の保存期間（7 日）を過ぎた記録が、ファイルの保存で実際に消えることは、確かめていない（F-G70）。
- 種類の違うトークンで鍵と `iss` を分けること（D3c の一部）は、未実装である。ID トークンとアクセストークンは、同じ鍵と `iss` で出す。
- secure の営業 AI エージェント（Claude）が、質問から提出まで道具を呼んで進めることは、画面の基本の流れで確かめた。Claude の答え方そのものの良し悪しと、道具の順を外れる頻度は、確かめていない。
