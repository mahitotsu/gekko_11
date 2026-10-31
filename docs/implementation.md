# 実装の構成と動かし方

このリポジトリの実装の技術スタック、フォルダ構成、動かし方、簡略化した点、まだ確かめていないことを示す。実装は 2 つある。業務の流れを 1 つのプロセスの中で動かす実装と、トークンの結び直しを k3d のクラスタで確かめる試作である。

**この文書の読み手:** 実装を読む人、動かす人、手を入れる人。Node.js と npm を使える。クラスタの試作を動かすなら、Docker と Kubernetes の基本も知っている。読んだ後に、どのフォルダに何があるかが分かり、サービスを起動してテストを回せる。構成と標準仕様は[アーキテクチャ](architecture.md)、シナリオと再現手順は[シナリオ](scenarios.md)にある。

## 要旨
- **構成:** npm workspaces で、5 つのサービスと共通部品を置き、1 つのプロセスの中で、固定のポートで動かす。クラスタの試作は、`services/insurer-auth`（Spring Authorization Server）、`packages/token-guard`、`deploy/` に置く。
- **クラスタの試作:** k3d の上で、SPIRE、Envoy、token-guard、認可サーバーが、トークン A、B、C の結び直しと、防御 D26、D27 を動かす。業務のサービスは、まだ載せていない。
- **動かし方:** `npm install` と `npm test` が、全シナリオで悪い実装の攻撃成功と、良い実装の拒否を確かめる。`npm run dev` が 5 つのサービスを起動する。
- **悪い実装は、教材のための意図的な実装である:** 本番の部品として使わない。環境変数で選び、指定のないものは良い実装で動く。
- **まだ確かめていないこと:** 本物の Claude とブラウザのパスキーでの動作、顧客のアプリの画面。

## 1. 技術スタックは、TypeScript と軽量な Web の部品である
前提は、Node.js 24 以上、npm 11 以上。

| 領域 | 使うもの | 使う場所 |
|---|---|---|
| 言語、実行 | TypeScript、tsx | 全体 |
| Web サーバー | Hono、`@hono/node-server` | 5 つのサービス |
| トークンと署名 | jose（JWT、JWS、鍵） | 認可サーバー、保険会社のシステム、事務サービス、共通部品 |
| passkey | `@simplewebauthn/server`、`@simplewebauthn/browser` | 認可サーバー、保険会社のシステム、顧客のアプリ |
| 内容の正規化 | canonicalize（JCS） | 共通部品 |
| MCP | `@modelcontextprotocol/sdk`、zod | 事務サービス、営業 AI エージェント |
| AI | `@anthropic-ai/claude-agent-sdk` | 営業 AI エージェント |
| テスト | vitest | `test/` |
| 認可サーバー（クラスタ） | Java 21、Spring Boot 3.5、Spring Authorization Server 1.5 | `services/insurer-auth` |
| クラスタと基盤 | k3d 5.9（k3s 1.35）、SPIRE 1.15、spiffe-helper 0.12、Envoy 1.31 | `deploy/` |

## 2. フォルダ構成は、サービスごとの `packages/` と、テストである
```text
packages/
  shared/            共通部品（トークン、案、正規化、照合、設定）
  insurer-auth/      認可サーバー（本人確認、トークンの発行と替え、登録と失効）
  insurer-backend/   保険会社のシステム（トークンと申込みの検証、契約の記録、直送）
  insurer-mcp/       事務サービス（営業 AI エージェントが呼ぶ MCP サーバー。トークンを替えて保険会社のシステムを呼ぶ）
  sales-agent/       営業 AI エージェント（Claude Agent SDK。決まった台本でも動く）
  customer-app/      顧客のアプリ（最小限。画面は未実装）
test/                シナリオのテストと、テスト用の認証器・世界
  token-guard/       クラスタで、各 Pod の Envoy から呼ばれ、トークンを確かめ、替える
  hop-app/           クラスタの試作で、各サービスの役を演じる中継アプリ
services/
  insurer-auth/      認可サーバー（Spring Authorization Server。クラスタで使う）
deploy/              クラスタの構成、組み立てのスクリプト、確かめ
scripts/dev.ts       5 つのサービスをまとめて起動する
```

`packages/insurer-auth` は、プロセスの中の実装の認可サーバーで、クラスタでは `services/insurer-auth` が代わる。

主なファイルは、次のとおり。

| ファイル | 役割 |
|---|---|
| `packages/shared/src/tickets.ts` | トークンの検証。悪い実装を含む |
| `packages/shared/src/canonical.ts` | JCS による正規化と、ハッシュ |
| `packages/shared/src/offers.ts` | 保険会社が署名した案と、提示集合 |
| `packages/shared/src/reconcile.ts` | 顧客の写しと、直送された通知の照合 |
| `packages/shared/src/config.ts` | ポート、URL、動作モード |
| `packages/insurer-auth/src/issuer.ts` | トークンの発行。悪い発行を含む |
| `packages/insurer-auth/src/config.ts` | 発行の仕方の切り替え（項目ごとの悪い発行） |
| `packages/insurer-auth/src/server.ts` | トークンの替え、有効性の問い合わせ、失効 |
| `packages/insurer-backend/src/verify/ticket.ts` | 保険会社のシステムでのトークンの検証 |
| `packages/insurer-backend/src/verify/seal.ts` | 署名の検証 |
| `packages/insurer-backend/src/app.ts` | 申込みの検証と、2 段の署名の連鎖 |
| `packages/insurer-mcp/src/core-ticket.ts` | 保険会社のシステムを呼ぶトークンの用意。悪い実装を含む |
| `test/scenarios.test.ts` | 21 のシナリオ、基本の流れ、補足のテスト |
| `services/insurer-auth/src/main/java/jp/gekko11/insurerauth/` | 認可サーバーの拡張点（SAN の照合、交換の前の確かめ、トークンの形） |
| `packages/token-guard/src/verify.ts` | 受け口の確かめ。D26 と D27 を含む |
| `packages/token-guard/src/defenses.ts` | vulnerable で防御を外す受け口。secure のイメージには入れない |
| `deploy/render.ts` | 名前空間ごとのマニフェスト（Envoy の設定、NetworkPolicy を含む） |
| `deploy/verify/verify.ts`、`deploy/verify/probe.ts` | クラスタの確かめと、クラスタの中で顧客や攻撃者を演じる役 |

## 3. サービスは固定ポートで動き、環境変数で設定する
| サービス | ポート | 環境変数 |
|---|---|---|
| customer-app | 4000 | `CUSTOMER_APP_PORT` |
| insurer-auth | 4001 | `INSURER_AUTH_PORT` |
| sales-agent | 4002 | `SALES_AGENT_PORT` |
| insurer-mcp | 4003 | `INSURER_MCP_PORT` |
| insurer-backend | 4004 | `INSURER_BACKEND_PORT` |

ポートが固定なので、テストファイルは並列に動かさない（`vitest.config.ts`）。

```sh
npm install
npm test               # 期待する結果: 94 passed
cp .env.example .env   # Claude を使うなら CLAUDE_CODE_OAUTH_TOKEN を貼る
npm run dev            # 5 つのサービスが起動する
```

クラスタの試作は、次のコマンドで動かす。前提は、Docker（cgroup v2）、k3d、kubectl である。Java は、Docker の中で使う。

```sh
npm run cluster:up       # k3d のクラスタを作る
npm run cluster:deploy   # SPIRE、イメージ、secure と vulnerable の名前空間を置く
npm run cluster:verify   # 期待する結果: 全て期待どおり（17 項目 × 2 つの名前空間）
npm run cluster:down     # クラスタを消す
```

| 動くもの | ポート | 主な環境変数 |
|---|---|---|
| 認可サーバー | 8443（TLS、証明書は任意） | `ISSUER`、`NAMESPACE`、`SVID_DIR` |
| sales-agent の受け口（Envoy） | 8443（TLS、DPoP） | — |
| insurer-mcp、insurer-backend の受け口（Envoy） | 9443（mTLS） | — |
| Envoy の出口 | 15101（認可サーバー）、15102（次の段） | — |
| token-guard、hop-app | 9100、8080（Pod の中だけ） | `SERVICE`、`INGRESS_PROOF`、`ALLOWED_CALLERS`、`NEXT_SERVICE`、`DEFENSES_OFF` |

認可サーバーの単体の確かめ（JUnit）は、`services/insurer-auth` で、Maven のイメージを使って `mvn test` を回す。

`.env` に `CLAUDE_CODE_OAUTH_TOKEN` がなければ、営業 AI エージェントは決まった台本で動く。値は `claude setup-token` で取得する。`.env` は git に入れない。文書とコードに値を書かない。

## 4. 悪い実装は、環境変数で選ぶ
`INSURER_MODE=bad` が全体、`INSURER_MODE_BACKEND=bad`、`INSURER_MODE_MCP=bad`、`INSURER_MODE_AUTH=bad` がサービス単位である。シナリオごとの細かい切り替え（`BACKEND_TICKET_CHECK=no-aud` など）は、[scenarios.md](scenarios.md) の一覧にある。

クラスタでは、vulnerable の名前空間の token-guard だけが、`DEFENSES_OFF`（例: `D26,D27`）で防御を外す。secure のイメージは、この受け口を除いてビルドする。コードの冒頭に、悪い実装を含む旨を書く。

## 5. 簡略化した点
次の 6 つは、プロセスの中の実装の簡略化である。
- **mTLS は模擬である:** `mtls-only` では、事務サービスが付けるヘッダー `x-peer` を、通信相手の認証結果とみなす。実際の TLS は使わない。
- **替えるときに `actor_token` を使わない:** 替えを頼む窓口は、クライアント認証（Basic）で自分を示す。RFC 8693 の `actor_token` は省いた。
- **証明を送信者の鍵に結ばない:** DPoP と mTLS での結び付けと、証明書によるクライアント認証（[アーキテクチャ](architecture.md)の 4-3）は、まだない。替えを頼む窓口は、共有の秘密で自分を示す。盗んだトークンと秘密があれば、替えられる。
- **ログインは固定ユーザーである:** alice、bob、mallory が、パスワード `demo` で入れる。
- **パスキーの署名回数を見ない:** 同期されるパスキーは回数が 0 のままのため、重複は `nonce` で防ぐ。
- **記憶はメモリ上にある:** 認可サーバーと保険会社のシステムの記憶、鍵は、メモリ上に作る。再起動で消える。

次の 4 つは、クラスタの試作の簡略化である。
- **業務のサービスがない:** 各サービスの役は hop-app が演じ、確かめた主張を返すだけである。案、署名、契約の記録は、クラスタにない。
- **確かめの役は、乗っ取られた複製として動く:** probe は、そのサービスの ServiceAccount で動き、同じ SPIFFE ID を持つ。別の SVID が要る役は、別のノードに置く（F-G53）。
- **認可サーバーの記憶と鍵は、メモリ上にある:** 再起動で消える。ログインは固定ユーザーで、パスキーはない。
- **`actor_token` は、替えるたびに取り直す:** SVID が入れ替わると、前の証明書に結んだ `actor_token` は使えないためである（F-G54）。

## 6. まだ確かめていないこと
- 本物の Claude（Agent SDK）での動作と、ブラウザのパスキー（Windows Hello 等）での署名は、実行して確かめていない。テストは、台本の営業 AI エージェントとソフトウェア認証器で通っている。
- 顧客のアプリの画面は、まだない。顧客の操作は、テストの中でソフトウェア認証器と台本が行う。
- [シナリオ](scenarios.md)の防御のうち、次の 6 つは、再現するテストがない。シナリオ 22 と 23 も、まだテストがない。
  - **画面とともに未実装:** 顧客のアプリが ID トークンを確かめる（D21）、案の署名を確かめてから示す（D22）、確認画面を署名する内容から作る（D23）。
  - **クラスタの試作だけで確かめた:** 送信者の鍵への結び付け（D26）と、呼ぶ相手の SPIFFE ID の確かめ（D27）、替えを頼む者の証明書による認証（D4 の設計）。`npm run cluster:verify` で確かめ、`npm test` のテストはない。
  - **運用で行う:** 記録による監査（D25）。
- SVID が入れ替わった直後に、正規の連鎖が一時的に拒まれる（F-G54）。接続の寿命の上限か、取り直しは、まだない。
- 種類の違うトークンで鍵と `iss` を分けること（D3c の一部）は、未実装である。ID トークンとアクセストークンは、同じ鍵と `iss` で出す。
