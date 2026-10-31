#!/usr/bin/env bash
# k3d のクラスタを組み立てる。使い方: deploy/cluster.sh up|deploy|down（確かめは npm run cluster:test）
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=gekko11
TRUST_DOMAIN=gekko11.internal
NAMESPACES=(secure vulnerable)
SERVICE_ACCOUNTS=(insurer-auth sales-agent insurer-mcp insurer-backend customer-app intruder operator auditor)
# SVID の有効期間（秒）。入れ替わりを観察できるよう、短くする。
SVID_TTL=600

spire() { kubectl -n spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server "$@"; }

entry() {
  local id="$1"; shift
  if spire entry show -spiffeID "$id" | grep -q "Entry ID"; then return; fi
  spire entry create -spiffeID "$id" "$@" >/dev/null
  echo "entry: $id"
}

up() {
  k3d cluster list "$CLUSTER" >/dev/null 2>&1 || k3d cluster create --config deploy/k3d/cluster.yaml
}

deploy() {
  kubectl apply -k deploy/k8s/spire
  kubectl -n spire rollout status statefulset/spire-server --timeout=180s
  kubectl -n spire rollout status daemonset/spire-agent --timeout=180s

  local node="spiffe://$TRUST_DOMAIN/ns/spire/sa/spire-agent"
  entry "$node" -node -selector "k8s_psat:cluster:$CLUSTER"
  for ns in "${NAMESPACES[@]}"; do
    for sa in "${SERVICE_ACCOUNTS[@]}"; do
      entry "spiffe://$TRUST_DOMAIN/ns/$ns/sa/$sa" -parentID "$node" \
        -selector "k8s:ns:$ns" -selector "k8s:sa:$sa" -x509SVIDTTL "$SVID_TTL"
    done
  done

  # secure と vulnerable で、防御を外す受け口を含むかが違う（D-20）
  local images=(gekko11/insurer-mcp:dev)
  docker build -q -t gekko11/insurer-mcp:dev services/insurer-mcp
  for ns in "${NAMESPACES[@]}"; do
    docker build -q --build-arg VARIANT="$ns" -t "gekko11/insurer-auth:$ns" services/insurer-auth
    docker build -q --build-arg VARIANT="$ns" -t "gekko11/insurer-backend:$ns" services/insurer-backend
    docker build -q -f deploy/node.Dockerfile --build-arg VARIANT="$ns" -t "gekko11/node:$ns" .
    images+=("gekko11/insurer-auth:$ns" "gekko11/insurer-backend:$ns" "gekko11/node:$ns")
  done
  k3d image import -c "$CLUSTER" "${images[@]}"

  # 営業 AI エージェントの Claude の認証情報は、secure の名前空間にだけ置く（D-23）。値は .env から読み、どこにも書かない
  kubectl create namespace secure --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  local token
  token=$(grep -s '^CLAUDE_CODE_OAUTH_TOKEN=' .env | cut -d= -f2- || true)
  if [ -n "$token" ]; then
    printf %s "$token" | kubectl -n secure create secret generic claude --from-file=token=/dev/stdin --dry-run=client -o yaml \
      | kubectl apply -f - >/dev/null
  else
    echo "注意: .env に CLAUDE_CODE_OAUTH_TOKEN がないので、secure の営業 AI エージェントは台本で動く"
  fi

  for ns in "${NAMESPACES[@]}"; do
    node deploy/render.ts "$ns" | kubectl apply -f -
    # 設定やイメージを替えたら、Pod を作り直す（Envoy は設定を読み直さない）
    kubectl -n "$ns" rollout restart deployment
  done
  for ns in "${NAMESPACES[@]}"; do
    kubectl -n "$ns" rollout status deployment --timeout=300s
  done
}

case "${1:-}" in
  up) up ;;
  deploy) deploy ;;
  down) k3d cluster delete "$CLUSTER" ;;
  *) echo "使い方: $0 up|deploy|down" >&2; exit 2 ;;
esac
