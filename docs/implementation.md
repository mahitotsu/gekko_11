# 実装の構成と動かし方

このリポジトリの実装の技術スタック、フォルダ構成、動かし方、簡略化した点、まだ確かめていないことを示す。

**この文書の読み手:** 実装を読む人、動かす人、手を入れる人。Docker と Node.js を使え、Kubernetes の基本（Pod、名前空間）を知っている。Java と Python は手元に要らない。読んだ後に、どのフォルダに何があるかが分かり、クラスタを組み立ててテストを回せる。構成と標準仕様は[アーキテクチャ](architecture.md)、シナリオと再現手順は[シナリオ](scenarios.md)にある。

## 要旨
- **構成:** サービスごとに言語を選び、k3d の 1 つのクラスタの secure と vulnerable の名前空間で動かす（D-22）。ログインサーバーは Keycloak に Java の拡張を足したものである。保険会社のシステム、認可サーバー、監査サービスは Java、事務サービスは Python、それ以外は TypeScript である。監査の記録は、Alloy が名前空間ごとの Loki に集める（D-30）。
- **動かし方:** `npm test` が、型の検査、lint、3 つの言語の単体テストを回す。`npm run cluster:deploy` がクラスタを組み立て、`npm run cluster:test` が全シナリオと画面のテストを確かめる。画面は、ブラウザで `http://app.secure.localhost:8081` を開いて使う。監査の画面は `http://audit.secure.localhost:8081` である。
- **防御を外す受け口は、vulnerable のイメージだけにある:** 防御の ID ごとに、管理のポートで実行中に外す。教材のための意図的な実装で、本番の部品として使わない（D-24）。
- **営業 AI エージェント:** 顧客と AG-UI 1.0 で会話する（D-29）。secure では本物の Claude（既定は Haiku）、vulnerable では台本で動く（D-23）。
- **まだ確かめていないこと:** 本物の認証器は、Windows Hello でだけ確かめた。ブラウザは、VS Code に内蔵されたブラウザと Chrome である（F-G98、F-G99）。ほかのブラウザと認証器では、確かめていない。記録が 7 日で消えることも、確かめていない。

## 1. 技術スタックは、サービスごとに選んだ言語と、k3d の基盤である
| 領域 | 使うもの | 使う場所 |
|---|---|---|
| ログインサーバー | Keycloak 26.8.1、Java 21 の拡張（取決めの範囲の処理、発行の記録） | `services/insurer-login` |
| 認可サーバー | Java 21、Spring Boot 3.5、Spring Authorization Server 1.5、Spring Security の Resource Server 6.5 | `services/insurer-auth` |
| 保険会社のシステム | Java 21、Spring Boot 3.5、nimbus-jose-jwt、java-json-canonicalization（JCS）、webauthn4j | `services/insurer-backend` |
| 事務サービス | Python 3.12、FastMCP 4.1、httpx2 | `services/insurer-mcp` |
| 監査サービス | Java 21、Spring Boot 3.5、Spring Security の OAuth2 Client 6.5、Thymeleaf、java-json-canonicalization（JCS） | `services/insurer-audit` |
| 営業 AI エージェント | TypeScript、Claude Agent SDK 0.3.302、@ag-ui/core 1.0.3（AG-UI の型と確かめ）、MCP の SDK、Hono | `packages/sales-agent` |
| token-guard | TypeScript、Hono、jose | `packages/token-guard` |
| 顧客のアプリ | 画面は React 19、Vite 7、@ag-ui/client、@simplewebauthn/browser、react-markdown。BFF は Hono、openid-client、jose、canonicalize（JCS） | `packages/customer-app` |
| クラスタと基盤 | k3d 5.9（k3s 1.35）、SPIRE 1.15、spiffe-helper 0.12、Envoy 1.31、NetworkPolicy | `deploy/` |
| 記録の集約 | Grafana Alloy 1.20（`loki.source.kubernetes`）、Grafana Loki 3.7 | `deploy/k8s/logging/`、`deploy/render/logging.ts` |
| テスト | JUnit、pytest、vitest、Playwright 1.64（Docker のブラウザに playwright-core でつなぐ） | 各サービスの `test`、`test/cluster/`、`test/ui/` |
| lint | ESLint（typescript-eslint の推奨と、React の hooks の 2 つの規則）、ruff。整形の道具は使わない | `eslint.config.js`、`services/insurer-mcp` |

TypeScript は、Node.js 24 の型の取り除きで、そのまま動かす。Java と Python は、Docker の中でビルドし、テストする。部品を選んだ理由は、判断（D-16、D-19、D-22、D-30、D-31、D-35、D-47）にある。

## 2. フォルダ構成は、言語ごとのサービスと、クラスタの組み立てと、テストである
```text
services/
  insurer-login/     ログインサーバー（Keycloak の realm の設定、拡張、画面。ログイン、利用者の名簿、本人確認の属性、passkey、A と ID トークンと P の発行）
  insurer-auth/      認可サーバー（A の取り込み、B と C への交換、連絡先の登録、passkey の公開鍵の取り次ぎ、失効、有効性の問い合わせ）
  insurer-backend/   保険会社のシステム（商品の規則と試算、案の確かめと署名、申込みの検証、契約の記録、直送、監査の役への記録）
  insurer-mcp/       事務サービス（MCP の道具と、ツールの呼び出しの記録）
  insurer-audit/     監査サービス（監査の担当のログイン、記録の読み手、突き合わせ、監査の画面）
packages/
  sales-agent/       営業 AI エージェント（AG-UI の受け口、Claude Agent SDK。台本でも動く）
  customer-app/      顧客のアプリ（web/ が画面、src/ が BFF と受信箱）
  token-guard/       各 Pod で、Envoy から呼ばれ、トークンを確かめ、替える
deploy/              クラスタの構成（k3d、SPIRE、記録の集約）、マニフェストの生成（入口と Loki を含む）、組み立てのスクリプト、Node のイメージ
test/cluster/        クラスタのシナリオのテストと、クラスタの中で役を演じる probe
test/ui/             画面のテスト（Docker の Playwright のブラウザにつなぐ）
scripts/             Java と Python の単体テストと、Python の lint（ruff）を Docker で回すスクリプト
```

主なファイルは、次のとおり。

| ファイル | 役割 |
|---|---|
| `services/insurer-login/realm/insurer.json` | 利用者、役割、クライアント、スコープ `apply` と `passkeys`、passkey の設定（RP ID、重ねての登録の拒否、登録と削除の画面の文言）、SPIRE との信頼の設定、A の有効期間、更新のトークンの使い回しの拒否（G31）、ログインの上限 |
| `services/insurer-login/src/main/java/jp/gekko11/insurerlogin/` | 取決めの範囲の処理と、A の発行の記録（D-39） |
| `services/insurer-login/theme/insurer/` | ログインの画面。標準の画面を引き継ぎ、passkey の登録とログインのスクリプトだけを替える。登録は名前を尋ねず、作った環境と日時を名前にする（D-42、D-43）。ログインは、確認画面を待つ間、待っていることを示して操作を止める（D-44） |
| `services/insurer-auth/src/main/java/jp/gekko11/insurerauth/` | 認可サーバーの拡張点（SAN の照合、A の取り込み（G28）、交換の前の確かめ、トークンの形、有効性の問い合わせ） |
| `services/insurer-backend/src/main/java/jp/gekko11/insurerbackend/ApplicationController.java` | 試算の受け口、提示の確定（G30）、申込みの内容の確かめ（G9、G11〜G18） |
| `services/insurer-backend/src/main/java/jp/gekko11/insurerbackend/Products.java` | 商品の規則と計算（G30。P-17） |
| `services/*/src/vulnerable/` | vulnerable のビルドだけに入る、防御を外す受け口 |
| `services/insurer-audit/src/main/java/jp/gekko11/insureraudit/Reconciler.java` | 契約ごとの突き合わせ（G25）。書いた者を Pod の印で決める（D-32）。比べた値と書いた者を、根拠の強さごとにまとめて、画面と JSON に渡す |
| `services/insurer-audit/src/main/java/jp/gekko11/insureraudit/ClusterRecords.java` | Loki の問い合わせと、保険会社のシステムの自己申告（`/audit/records`）の読み手 |
| `services/insurer-audit/src/main/java/jp/gekko11/insureraudit/SecurityConfig.java` | 監査の担当のログイン（D-31） |
| `deploy/k8s/logging/alloy.yaml` | Alloy の設定。名前空間ごとに、監査の記録だけをその名前空間の Loki へ送る |
| `packages/token-guard/src/verify.ts` | 受け口の確かめ（G1、G5〜G8、G10、G20、G26、G27） |
| `packages/token-guard/src/exchange.ts` | 出口の交換（G2） |
| `packages/customer-app/web/checks.ts` | 画面の確かめ（G21〜G23） |
| `packages/customer-app/web/components/` | 画面（ログイン、登録、カードで進む申込み、確認、署名、照合。D-34） |
| `packages/customer-app/src/bff.ts` | BFF（D-41）。ログイン（頼まれたら passkey の登録も。D-42）、本人の passkey の一覧の読み取り（D-43）、セッション、更新（P-18）、ID トークンの確かめ（G21）、受信箱の番号の登録（D-26）、営業 AI エージェントへの中継、CSRF の対策 |
| `packages/customer-app/web/auth.ts` | 画面の側のログイン。BFF の受け口を呼ぶだけで、トークンを持たない。端末の受信箱の番号を覚える |
| `packages/customer-app/web/passkey.ts` | passkey での署名（保険会社にある passkey に限る）と、一覧を端末に伝える Signal API（D-43） |
| `packages/customer-app/web/components/App.tsx` | 画面。「パスキー」の欄（一覧、この端末で使った印、作成、ログインサーバーに頼む削除。D-43）と、作成の促し |
| `packages/customer-app/web/controller.ts`、`conversation.ts` | 申込みの進め方と、会話の状態 |
| `packages/sales-agent/src/agui.ts` | AG-UI の受け口（`POST /agui`。RunAgentInput を確かめ、SSE でイベントを返す） |
| `packages/sales-agent/src/thread.ts` | 会話ごとの状態と、画面側の道具の呼び出しと待ち合わせ（D-29）。会話の記録を、秘密を伏せて書き出す（D-32） |
| `packages/sales-agent/src/claude.ts`、`scripted.ts` | Claude と台本。同じ道具を呼ぶ |
| `packages/sales-agent/src/draft.ts`、`submit.ts` | 書類の組み立てと、署名の揃った書類の提出（D-27） |
| `packages/customer-app/web/agent.ts` | 画面の側の AG-UI の接続と、画面側の道具の定義 |
| `packages/*/src/*.secure.ts`、`packages/customer-app/web/defenses.secure.ts` | secure のビルドで、防御を外す受け口と置き換えるファイル |
| `deploy/render.ts` | 名前空間ごとのマニフェストを組み立てて書き出す。変わった Deployment だけが更新されるよう、イメージと設定のハッシュを付ける |
| `deploy/render/` | マニフェストの部品。共通の値（`common.ts`。入口の名前、発行者、ポート）、サービスの一覧（`services.ts`）、Envoy の設定（`envoy.ts`）、Kubernetes の部品（`kubernetes.ts`）、入口（`entrance.ts`）、記録の集約（`logging.ts`）、NetworkPolicy（`network.ts`） |
| `test/cluster/scenarios.test.ts`、`test/cluster/expiry.test.ts` | probe で確かめるシナリオと補足のテスト |
| `test/ui/scenarios.test.ts`、`test/ui/flow.test.ts` | 画面のシナリオ（8、24）、G21 の補足、画面の基本の流れ |
| `test/cluster/probe/probe.ts` | クラスタの中で、顧客、乗っ取られた複製、攻撃者、運用の担当、監査の役、監査の担当を演じる |

## 3. ポートと環境変数は、マニフェストの生成で決まる
前提は、Docker（cgroup v2、BuildKit）、k3d、kubectl、Node.js 24 以上、npm 11 以上である。

```sh
npm install
npm test                 # 型の検査、lint、3 つの言語の単体テスト
npm run cluster:up       # k3d のクラスタを作る
npm run cluster:deploy   # SPIRE、イメージ、secure と vulnerable の名前空間を置く
npm run cluster:test     # 全シナリオと画面のテスト（30 分ほど）。期待する結果: 全て通る
npm run cluster:down     # クラスタを消す
```

営業 AI エージェントを secure で Claude として動かすには、`.env` に `CLAUDE_CODE_OAUTH_TOKEN` を置いてから `cluster:deploy` を回す。値は `claude setup-token` で取得する。値は secure の名前空間の Secret にだけ入り、`.env` は git に入れない。文書とコードに値を書かない。値がなければ、secure でも台本で動く。

ブラウザは、入口を通って、名前空間ごとに次の名前に届く。secure はポート 8081、vulnerable は 8082 である。k3d の loadbalancer が、入口の NodePort（30081、30082）につなぐ。

| 名前 | 届く先 |
|---|---|
| `app.<名前空間>.localhost` | 顧客のアプリの配信元（画面、BFF、設定、提示の公開鍵、受信箱） |
| `login.<名前空間>.localhost` | ログインサーバー（ブラウザに出す経路だけ）。A の issuer は `http://login.<名前空間>.localhost:<ポート>/realms/insurer` である |
| `auth.<名前空間>.localhost` | 認可サーバー。B と C の issuer の名前で、ブラウザに出す経路はない（すべて 404） |
| `audit.<名前空間>.localhost` | 監査サービス（監査の画面と、同じ中身の JSON の受け口 `/api/contracts`） |

| 動くもの | ポート | 主な環境変数 |
|---|---|---|
| ログインサーバー | 8443（Envoy）、8080（Pod の中だけ） | `KC_HOSTNAME`、`KC_TRUSTSTORE_PATHS`。realm の設定が読む `NAMESPACE`、`TRUST_DOMAIN`、`AUTH_ISSUER`、`APP_ORIGIN`、`AUDIT_ORIGIN` |
| 認可サーバー | 8443（TLS、証明書は任意） | `ISSUER`、`NAMESPACE`、`SVID_DIR`、`RP_ID`、`WEBAUTHN_ORIGINS`、`LOGIN_ISSUER`、`LOGIN_JWKS_URL` |
| SPIRE の bundle の受け口 | 8443（`spire` の名前空間。証明書は `deploy/cluster.sh` が作り、`.secrets/` に置く） | — |
| 顧客のアプリ、監査サービスの受け口（Envoy） | 8443（TLS、証明書なし） | — |
| 営業 AI エージェントの受け口（Envoy） | 8443（mTLS。顧客のアプリの BFF だけ） | — |
| 事務サービス、保険会社のシステム、直送の受け口（Envoy） | 9443（mTLS） | — |
| 入口（Envoy） | 8080（Pod の中）、NodePort 30081 と 30082 | — |
| Envoy の出口 | 15101（認可サーバー）、15102（次の段）、15103（顧客のアプリ）、15104（顧客のアプリから、保険会社のシステムの提示の公開鍵）、15105（ログインサーバー）、15106（顧客のアプリの BFF から、営業 AI エージェント） | — |
| アプリ、token-guard | 8080、9100（Pod の中だけ） | `SERVICE`、`INGRESS_PROOF`、`PUBLIC_ORIGIN`、`ALLOWED_CALLERS`、`NEXT_SERVICE`、`CLAUDE_MODEL`、顧客のアプリは `ISSUER`、`RP_ID`、`APP_ORIGIN`、`LOGIN_URL`、`AGENT_URL`、`AGENT_ORIGIN_INTERNAL`、`AUTH_URL`、`AUTH_ORIGIN_INTERNAL`、`JWT_SVID_FILE`、監査サービスは `ISSUER`、`PUBLIC_ORIGIN`、`LOKI_URL` |
| Loki | 3100（名前空間の中の HTTP。Alloy と監査サービスだけが届く） | — |
| 管理のポート（vulnerable だけ） | 9090（token-guard）、9091（アプリ） | — |

イメージのビルドは、Maven、pip、npm の取り込みを BuildKit のキャッシュに置き、ビルドの間で使い回す。

`cluster:deploy` は、変わったものだけを更新する。何も変えずに回しても、Pod は作り直されない。イメージの中身、設定、Claude の認証情報、bundle の受け口の証明書が変わると、それを使う Pod だけが作り直される。

## 4. 防御は、vulnerable の管理のポートで、防御の ID ごとに外す
vulnerable のイメージでは、次の部品が、管理のポートで防御を切り替える。token-guard、ログインサーバー、認可サーバー、保険会社のシステム、顧客のアプリの配信元である。これらは、管理のポートで `GET /defenses` と `PUT /defenses`（例: `{"off": {"G7": "off"}}`）を受ける。顧客のアプリの画面は、開くときに配信元の `/defenses` を読み、外された G21〜G23 を飛ばす。営業 AI エージェントは、`PUT /tamper` で、乗っ取られた AI の書き換えを入れる。`PUT /forge-audit` は、本文をそのまま監査の記録として書き、ほかのサービスを名乗る記録の偽装を再現する。切り替えはメモリ上で行い、Pod は入れ替えない。どの防御をどの部品が受けるかは、[シナリオ](scenarios.md)の 2-3 の表にある。

secure のイメージは、ビルドの時点で、この受け口を含まない。Java とログインサーバーの拡張は Maven の profile、TypeScript はファイルの置き換えで分ける。画面は、置き換えた後にまとめるので、secure の画面は外す道を持たない。事務サービスは、外す防御を token-guard に移したので、イメージは 1 つである。

## 5. 簡略化した点
- **業務の記憶と鍵は、メモリ上か Pod の中にある:** 認可サーバーと保険会社のシステムの記憶（受信箱の番号、契約の記録、`nonce`）と、発行と提示の鍵は、起動ごとに作る。ログインサーバーは、Pod の中のファイルに記憶（登録した passkey を含む）を置き、起動ごとに realm の設定を読み込む。どちらも再起動で消える。受信箱の番号は、ログインのたびに BFF が登録し直す。ログインサーバーが passkey を忘れた後は、パスワードでログインする。保険会社に passkey がないので、画面が作成を促す。作り直すと、端末の古い passkey は置き換わる。
- **ログインは固定ユーザーである:** 顧客の alice、bob、mallory、hanako、carol と、監査の担当の kansa が、パスワード `demo` で入れる。顧客は、パスワードでログインした後に passkey を作り、次からは passkey で入る。本人確認の記録は、ログインサーバーの realm の設定に固定で持つ。`sub` は、利用者の ID を固定して、この名前にする。alice、bob、mallory はテストが使う。carol は、passkey を持たない利用者として、作成の促しのテストだけが使う。手で画面を試すときは hanako を使う。テストの申込みが、受信箱に混ざらないためである。監査の画面は、kansa で見る。同じブラウザで替えるときは、画面のサインアウトを使う。passkey でログインするときは、ログインの画面の「パスキーでログイン」を押す。
- **商品の規則と料率は、教材用の仮の値である:** 確定年金と終身年金の 2 商品で、年齢、性別、受取開始年齢で金額を変えない。年金の年額は、`月額 × 12 × 払込年数 ÷ 換算年数` を 1 万円単位に切り捨てる。換算年数は、確定年金が受取期間、終身年金が 15 年である。実在の料率ではない（P-17）。受取期間と年額の下限の例は I-A7 に沿わせた。
- **台本は、案を組み立てない:** vulnerable の名前空間と認証情報のない環境の台本は、既定の条件（確定年金は 10 年、払込は 25 年）の 4 案を提出する。案のカードで頼み直すと、そこで止まる。希望が案に届くのは、Claude が動く secure だけである。
- **passkey の署名回数を見ない:** 同期される passkey は回数が 0 のままのため、重複は `nonce` で防ぐ。
- **Keycloak の passkey の不具合を、設定で避ける:** resident key を「Required」にすると、名前のない passkey ができる。そのため、2 つの設定を組み合わせた（F-G92）。登録の画面のスクリプトも、写して直した（`services/insurer-login/theme/insurer/`）。版を上げるときは、どちらも確かめ直す。ログインの画面のスクリプトも、確認画面を待つ間の表示のために写した（D-44）。
- **ログインサーバーの静的なファイルを、キャッシュさせない:** 写したスクリプトを替えても、URL が変わらず、ブラウザが古いものを使い続けるためである（F-G101）。起動の引数 `--spi-theme--static-max-age=-1` で止めた。
- **確かめの役は、乗っ取られた複製として動く:** probe は、そのサービスの ServiceAccount で動き、同じ SPIFFE ID を持つ。別の SVID が要る役は、別のノードに置く（F-G53）。
- **上流への接続は、要求ごとにつなぎ直す:** SVID が入れ替わった後に、前の証明書の接続を使い回すと、新しい証明書に結んだトークンと食い違う。要求ごとに新しくつなぎ、そのときの SVID で示す（F-G54）。
- **`actor_token` は、替えるたびに取り直す:** SVID が入れ替わると、前の証明書に結んだ `actor_token` は使えないためである（F-G54）。
- **入口は、TLS なしの localhost である:** ブラウザと入口の間は、利用者の端末の中のループバックで、http で受ける。ブラウザは localhost を安全な文脈として扱うので、passkey と WebCrypto が動く（F-G62、F-G63）。本番では、信頼された証明書の HTTPS にする。issuer も http になる。
- **受信箱の番号は、端末の保存領域にある:** 番号を持つ者は、その受信箱を読める（D-26）。署名済み申込の写しも、同じ保存領域に置く。
- **新しい申し込みで捨てた会話は、サーバーに残る:** 画面は要求を止めて会話を捨てるが、営業 AI エージェントには、使われなくなるまで最大 15 分残る。提出の途中なら、始め直しても契約になることがある（D-34）。
- **BFF のセッションは、メモリにある:** 顧客のアプリの BFF は、セッション、トークン、DPoP の鍵を、1 つの複製のメモリに持つ。再起動で消え、ログインし直しになる。複製を増やすには、セッションの置き場所を分ける必要がある（D-41）。
- **画面のファイルが大きい:** まとめたスクリプトは、分割せず、約 850 kB ある。教材の規模なので、読み込みの遅さを問題にしない（D-40）。
- **更新できなくなると、最初からやり直す:** 無操作が 30 分続くか、ログインから 1 時間経つと、トークン A を更新できない。ログインし直すと、入力した内容は消える（D-34、P-18）。
- **会話の状態は、営業 AI エージェントのメモリにある:** threadId ごとの会話（Claude の会話、直前の提示、署名した書類）を、1 つの複製のメモリに持つ。再起動で消え、15 分使われなければ捨てる。会話は、ログインの上限の 1 時間までに終える（P-18）。
- **記録の集約は、教材の規模である:** Loki は、名前空間ごとに 1 つのプロセスで動き、認証を持たない。記録は、Pod の一時的な領域（emptyDir）のファイルに保存する。Pod を作り直すと、記録は消える。Alloy も 1 つで、止まっている間の記録は届かない。
- **サインアウトは、もう一方のアプリのセッションを終わらせない:** 押したアプリとログインサーバーのログインだけが終わる（D-33）。ログインサーバーが再起動した後は、ID トークンを示せないので、確認の画面を 1 回押す（F-G80）。
- **同じログインの間は、前回の取決めの範囲が残る:** ログインサーバーは、範囲を求めない次の要求にも、前回の範囲を載せる（F-G78）。顧客のアプリの BFF は A を求めるたびに範囲を示すので、A が前の範囲になることはない。P には範囲が載るが、P の受け口は読まない。
- **Pod の起動が遅い:** ログインサーバーは、起動に 1 分から 3 分かかる。
- **監査は、AI への指示とモデルの変更を見ない:** 会話の記録に、動いたモデルの名前だけを残す。指示（プロンプト）の変更の記録と、その監査は作っていない。
- **probe の顧客の役も残る:** 多くのシナリオは、クラスタの中の probe が顧客を演じる。署名と DPoP の proof には、入口の公開名を使う。

## 6. まだ確かめていないこと
- Signal API で一覧を伝えても、端末の古い passkey は消えなかった（F-G98、D-43）。確かめたのは、Windows の VS Code に内蔵されたブラウザと Windows Hello である。Chrome と Edge では、確かめていない。
- 本物の認証器での手の確かめは、Windows Hello だけである（F-G98、F-G99）。ログインから照合までを手で通したのは、Windows の VS Code に内蔵されたブラウザだけである。Chrome では、passkey でのログインと署名だけを手で確かめた。Edge、Safari、Firefox と、ほかの認証器（スマートフォンの passkey など）では、確かめていない。自動テストは、Chromium と仮想の認証器で行う（F-G63）。
- passkey の確認画面が出るまでの時間は、Windows Hello でだけ測った（F-G99、D-44）。Chrome で 1.8 秒ほど、VS Code に内蔵されたブラウザで 5 秒ほどだった。Chrome では、ログインと署名の両方で、待つ間の表示と操作の停止を手でも確かめた。Edge、ほかの OS、ほかの認証器では、測っていない。
- Loki の保存期間（7 日）を過ぎた記録が、ファイルの保存で実際に消えることは、確かめていない（F-G70）。
- 種類の違うトークンで鍵と `iss` を分けること（G3c の一部）は、ログインサーバーの中では未実装である。ID トークンと A は、同じ鍵と `iss` で出す。
- secure の営業 AI エージェント（Claude）が、質問から提出まで道具を呼んで進めることは、画面の基本の流れで確かめた。Claude の答え方そのものの良し悪しと、道具の順を外れる頻度は、確かめていない。
