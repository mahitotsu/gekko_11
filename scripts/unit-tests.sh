#!/usr/bin/env bash
# サービスごとの単体テスト（Java と Python）。手元に Java と Python を入れず、Docker の中で回す。
# Maven と pip の取り込みは、手元のキャッシュ（~/.m2、~/.cache/pip）を使い回す。
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p ~/.m2 ~/.cache/pip
USER_ARGS=(-u "$(id -u):$(id -g)" -e HOME=/tmp)

for service in insurer-auth insurer-backend insurer-audit; do
  echo "== $service（JUnit）"
  docker run --rm "${USER_ARGS[@]}" -v ~/.m2:/var/maven/.m2 -e MAVEN_CONFIG=/var/maven/.m2 \
    -v "$PWD/services/$service":/src -w /src maven:3.9-eclipse-temurin-21 \
    mvn -q -B -Duser.home=/var/maven test
done

echo "== insurer-mcp（pytest）"
docker run --rm "${USER_ARGS[@]}" -e PYTHONDONTWRITEBYTECODE=1 -e PIP_CACHE_DIR=/pip-cache -v ~/.cache/pip:/pip-cache \
  -v "$PWD/services/insurer-mcp":/src -w /src python:3.12-slim \
  sh -c 'pip install -q --user -r requirements-dev.txt && python -m pytest -q -p no:cacheprovider'
