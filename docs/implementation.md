# 実装の構成と動かし方

このリポジトリの実装の技術スタック、フォルダ構成、動かし方、簡略化した点、まだ確かめていないことを示す。

**この文書の読み手:** 実装を読む人、動かす人、手を入れる人。Node.js と npm を使える。読んだ後に、どのフォルダに何があるかが分かり、サービスを起動してテストを回せる。構成と標準仕様は[アーキテクチャ](architecture.md)、シナリオと再現手順は[シナリオ](scenarios.md)にある。

## 要旨
- **構成:** npm workspaces で、5 つのサービス（`packages/` の 5 つ）と共通部品（`packages/shared`）を置く。サービスは、固定のポートで動く。
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
scripts/dev.ts       5 つのサービスをまとめて起動する
```

主なファイルは、次のとおり。

| ファイル | 役割 |
|---|---|
| `packages/shared/src/tickets.ts` | トークンの検証。悪い実装を含む |
| `packages/shared/src/canonical.ts` | JCS による正規化と、ハッシュ |
| `packages/shared/src/offers.ts` | 保険会社が署名した案と、提示集合 |
| `packages/shared/src/reconcile.ts` | 顧客の写しと、直送された通知の照合 |
| `packages/shared/src/config.ts` | ポート、URL、動作モード |
| `packages/insurer-auth/src/issuer.ts` | トークンの発行。悪い発行を含む |
| `packages/insurer-backend/src/verify/ticket.ts` | 保険会社のシステムでのトークンの検証 |
| `packages/insurer-backend/src/verify/seal.ts` | 署名の検証 |
| `packages/insurer-backend/src/app.ts` | 申込みの検証と、2 段の署名の連鎖 |
| `packages/insurer-mcp/src/core-ticket.ts` | 保険会社のシステムを呼ぶトークンの用意。悪い実装を含む |
| `test/scenarios.test.ts` | 21 シナリオと基本の流れ |

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
npm test               # 期待する結果: 89 passed
cp .env.example .env   # Claude を使うなら CLAUDE_CODE_OAUTH_TOKEN を貼る
npm run dev            # 5 つのサービスが起動する
```

`.env` に `CLAUDE_CODE_OAUTH_TOKEN` がなければ、営業 AI エージェントは決まった台本で動く。値は `claude setup-token` で取得する。`.env` は git に入れない。文書とコードに値を書かない。

## 4. 悪い実装は、環境変数で選ぶ
`INSURER_MODE=bad` が全体、`INSURER_MODE_BACKEND=bad`、`INSURER_MODE_MCP=bad`、`INSURER_MODE_AUTH=bad` がサービス単位である。シナリオごとの細かい切り替え（`BACKEND_TICKET_CHECK=no-aud` など）は、[scenarios.md](scenarios.md) の一覧にある。コードの冒頭に、悪い実装を含む旨を書く。

## 5. 簡略化した点
- **mTLS は模擬である:** `mtls-only` は、事務サービスが付けるヘッダー `x-peer` を、通信相手の認証結果とみなす。実際の TLS は使わない。
- **替えるときに `actor_token` を使わない:** 替えを頼む窓口は、クライアント認証（Basic）で自分を示す。RFC 8693 の `actor_token` は省いた。
- **証明を送信者の鍵に結ばない:** DPoP と mTLS での結び付けと、証明書によるクライアント認証（[アーキテクチャ](architecture.md)の 4-3）は、まだない。替えを頼む窓口は、共有の秘密で自分を示す。盗んだトークンと秘密があれば、替えられる。
- **ログインは固定ユーザーである:** alice、bob、mallory が、パスワード `demo` で入れる。
- **パスキーの署名回数を見ない:** 同期されるパスキーは回数が 0 のままのため、重複は `nonce` で防ぐ。
- **記憶はメモリ上にある:** 認可サーバーと保険会社のシステムの記憶、鍵は、メモリ上に作る。再起動で消える。

## 6. まだ確かめていないこと
- 本物の Claude（Agent SDK）での動作と、ブラウザのパスキー（Windows Hello 等）での署名は、実行して確かめていない。テストは、台本の営業 AI エージェントとソフトウェア認証器で通っている。
- 顧客のアプリの画面は、まだない。確認画面を内容から作る項目（[アーキテクチャ](architecture.md)の 6-3）は、画面を作るときに検証する。顧客の操作は、テストの中でソフトウェア認証器が行う。
- 顧客のアプリが案の署名を確かめる処理（[アーキテクチャ](architecture.md)の 4-4）は、画面とともにまだない。テストでは、顧客の操作を台本が行う。
