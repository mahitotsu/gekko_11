# syntax=docker/dockerfile:1
# Maven のローカルリポジトリは、BuildKit のキャッシュに置き、ビルドの間で使い回す（依存を毎回取り直さない）。
# VARIANT=vulnerable のときだけ、防御を外す受け口（src/vulnerable/java）を足す（D-24）。
FROM maven:3.9-eclipse-temurin-21 AS build
ARG VARIANT=secure
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    if [ "$VARIANT" = "vulnerable" ]; then P="-Pvulnerable"; fi; mvn -q -B package -DskipTests $P

FROM eclipse-temurin:21-jre
COPY --from=build /src/target/insurer-auth.jar /app/insurer-auth.jar
USER 1000
ENTRYPOINT ["java", "-jar", "/app/insurer-auth.jar"]
