# syntax=docker/dockerfile:1
# Maven のローカルリポジトリは、BuildKit のキャッシュに置き、ビルドの間で使い回す（依存を毎回取り直さない）。
# 監査サービスには、防御を外す受け口がないので、secure と vulnerable で同じイメージを使う。
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package -DskipTests

FROM eclipse-temurin:21-jre
COPY --from=build /src/target/insurer-audit.jar /app/insurer-audit.jar
USER 1000
ENTRYPOINT ["java", "-jar", "/app/insurer-audit.jar"]
