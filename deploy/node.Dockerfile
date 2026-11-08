# syntax=docker/dockerfile:1
# token-guard、営業 AI エージェント、顧客のアプリ、probe を入れる Node のイメージ。Node 24 は TypeScript をそのまま動かす。
# VARIANT=secure では、防御を外す受け口と、乗っ取りの再現を、ビルドの時点で除く（D-20）。

# 顧客のアプリの画面を、ブラウザ向けにまとめる（Vite）。secure は、外す道を持たない版に置き換えてからまとめる（D-24）
FROM node:24-slim AS web
ARG VARIANT=secure
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/customer-app/package.json packages/customer-app/
COPY packages/sales-agent/package.json packages/sales-agent/
COPY test/cluster/probe/package.json test/cluster/probe/
COPY packages/token-guard/package.json packages/token-guard/
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --workspace @gekko/customer-app
COPY packages/customer-app/src packages/customer-app/src
COPY packages/customer-app/web packages/customer-app/web
COPY packages/customer-app/vite.config.ts packages/customer-app/
RUN if [ "$VARIANT" = "secure" ]; then \
      mv packages/customer-app/web/defenses.secure.ts packages/customer-app/web/defenses.ts; \
    else rm packages/customer-app/web/defenses.secure.ts; fi && \
    npm run build -w @gekko/customer-app

FROM node:24-slim
ARG VARIANT=secure
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/customer-app/package.json packages/customer-app/
COPY packages/sales-agent/package.json packages/sales-agent/
COPY test/cluster/probe/package.json test/cluster/probe/
COPY packages/token-guard/package.json packages/token-guard/
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts --workspace @gekko/token-guard --workspace @gekko/sales-agent --workspace @gekko/customer-app --workspace @gekko/probe
COPY packages/token-guard/src packages/token-guard/src
COPY packages/sales-agent/src packages/sales-agent/src
COPY packages/customer-app/src packages/customer-app/src
# BFF は、ID トークンの確かめ（G21）に、画面と同じ確かめの処理を使う（D-41）
COPY packages/customer-app/web/checks.ts packages/customer-app/web/codec.ts packages/customer-app/web/
COPY --from=web /app/packages/customer-app/dist packages/customer-app/dist
COPY test/cluster/probe test/cluster/probe
RUN if [ "$VARIANT" = "secure" ]; then \
      mv packages/token-guard/src/defenses.secure.ts packages/token-guard/src/defenses.ts && \
      mv packages/sales-agent/src/tamper.secure.ts packages/sales-agent/src/tamper.ts && \
      mv packages/customer-app/src/defenses.secure.ts packages/customer-app/src/defenses.ts; \
    else rm packages/token-guard/src/defenses.secure.ts packages/sales-agent/src/tamper.secure.ts packages/customer-app/src/defenses.secure.ts; fi
USER 1000
