# token-guard、hop-app、probe を入れる Node のイメージ。Node 24 は TypeScript をそのまま動かす。
# VARIANT=secure では、防御を外す受け口を、ビルドの時点で除く（D-20）。
FROM node:24-slim
ARG VARIANT=secure
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/customer-app/package.json packages/customer-app/
COPY packages/insurer-auth/package.json packages/insurer-auth/
COPY packages/insurer-backend/package.json packages/insurer-backend/
COPY packages/insurer-mcp/package.json packages/insurer-mcp/
COPY packages/sales-agent/package.json packages/sales-agent/
COPY packages/token-guard/package.json packages/token-guard/
COPY packages/hop-app/package.json packages/hop-app/
RUN npm ci --omit=dev --ignore-scripts --workspace @gekko/token-guard --workspace @gekko/hop-app
COPY packages/token-guard/src packages/token-guard/src
COPY packages/hop-app/src packages/hop-app/src
COPY deploy/verify/probe.ts deploy/verify/probe.ts
RUN if [ "$VARIANT" = "secure" ]; then mv packages/token-guard/src/defenses.secure.ts packages/token-guard/src/defenses.ts; \
    else rm packages/token-guard/src/defenses.secure.ts; fi
USER 1000
