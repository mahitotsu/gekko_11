#!/usr/bin/env bash
# k3d のクラスタを組み立て、確かめる（段 0）。使い方: deploy/cluster.sh up|deploy|verify|down
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=gekko11
TRUST_DOMAIN=gekko11.internal
NAMESPACES=(secure vulnerable)
SERVICE_ACCOUNTS=(insurer-auth sales-agent insurer-mcp insurer-backend intruder)
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

  docker build -q -t gekko11/insurer-auth:dev services/insurer-auth
  for ns in "${NAMESPACES[@]}"; do
    docker build -q -f deploy/node.Dockerfile --build-arg VARIANT="$ns" -t "gekko11/node:$ns" .
  done
  k3d image import -c "$CLUSTER" gekko11/insurer-auth:dev gekko11/node:secure gekko11/node:vulnerable

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
  verify) node deploy/verify/verify.ts ;;
  down) k3d cluster delete "$CLUSTER" ;;
  *) echo "使い方: $0 up|deploy|verify|down" >&2; exit 2 ;;
esac
