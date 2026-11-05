# syntax=docker/dockerfile:1
# ログインサーバー（Keycloak）。製品に、取決めの範囲の処理と発行の記録の拡張を足す（D-35、D-39）。
# VARIANT=vulnerable のときだけ、防御を外す受け口（src/vulnerable）を足す（D-20）。
FROM maven:3.9-eclipse-temurin-21 AS build
ARG VARIANT=secure
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    if [ "$VARIANT" = "vulnerable" ]; then P="-Pvulnerable"; fi; mvn -q -B package -DskipTests $P

FROM quay.io/keycloak/keycloak:26.8.1
COPY --from=build /src/target/insurer-login-extension.jar /opt/keycloak/providers/insurer-login-extension.jar
COPY realm/insurer.json /opt/keycloak/data/import/insurer.json
# SPIFFE の JWT-SVID でのクライアント認証は preview で、既定で無効である（D-38）。
# 記憶は、教材の規模として、Pod の中のファイルに置く（implementation の 5 章）
RUN /opt/keycloak/bin/kc.sh build --db=dev-file --cache=local --features=spiffe,client-auth-federated
