#!/usr/bin/env bash
# k3d のクラスタを組み立てる。使い方: deploy/cluster.sh up|deploy|down（確かめは npm run cluster:test）
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=gekko11
TRUST_DOMAIN=gekko11.internal
NAMESPACES=(secure vulnerable)
SERVICE_ACCOUNTS=(insurer-auth insurer-login sales-agent insurer-mcp insurer-backend customer-app insurer-audit entrance intruder operator auditor)
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

# SPIRE の bundle の受け口の TLS の証明書（D-38）。SVID とは関係のない、使い捨ての自己署名の証明書で、一度だけ作る。
# ログインサーバーは、この証明書を信頼して、JWT-SVID を確かめる公開鍵を取る。
bundle_endpoint_cert() {
  local dir=.secrets/spire-bundle-endpoint
  if [ ! -f "$dir/tls.crt" ]; then
    mkdir -p "$dir"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$dir/tls.key" -out "$dir/tls.crt" -days 3650 \
      -subj "/CN=spire-server.spire.svc.cluster.local" \
      -addext "subjectAltName=DNS:spire-server.spire.svc.cluster.local" >/dev/null 2>&1
  fi
  kubectl create namespace spire --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n spire create secret tls spire-bundle-endpoint-tls --cert="$dir/tls.crt" --key="$dir/tls.key" --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null
  for ns in "${NAMESPACES[@]}"; do
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl -n "$ns" create configmap spire-bundle-ca --from-file=ca.crt="$dir/tls.crt" --dry-run=client -o yaml \
      | kubectl apply -f - >/dev/null
  done
}

# マニフェストを置き、設定（ConfigMap）が変わったときだけ、その設定を読むものを作り直す。
# これらは、設定を起動のときにだけ読み、設定の変更では更新が始まらない。Pod の定義の変更は、kubectl apply が更新する。
# 使い方: apply_and_restart_on_config_change <名前空間> <kustomize のフォルダ> <ConfigMap> <読むもの> ...
apply_and_restart_on_config_change() {
  local namespace="$1" dir="$2" applied
  shift 2
  applied=$(kubectl apply -k "$dir")
  while [ $# -gt 0 ]; do
    if grep -q "configmap/$1 configured" <<<"$applied"; then
      kubectl -n "$namespace" rollout restart "$2"
    fi
    shift 2
  done
}

deploy() {
  bundle_endpoint_cert
  apply_and_restart_on_config_change spire deploy/k8s/spire \
    spire-server-config statefulset/spire-server spire-agent-config daemonset/spire-agent
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
  # 記録の集約（D-30）。公開から 2 週間以上の版に固定する
  local images=(gekko11/insurer-mcp:dev gekko11/insurer-audit:dev)
  local external=(grafana/loki:3.7.8 grafana/alloy:v1.20.1)
  for image in "${external[@]}"; do docker pull -q "$image" >/dev/null; done
  docker build -q -t gekko11/insurer-mcp:dev services/insurer-mcp
  # 監査サービスには、防御を外す受け口がないので、両方の名前空間で同じイメージを使う
  docker build -q -t gekko11/insurer-audit:dev services/insurer-audit
  for ns in "${NAMESPACES[@]}"; do
    docker build -q --build-arg VARIANT="$ns" -t "gekko11/insurer-auth:$ns" services/insurer-auth
    docker build -q --build-arg VARIANT="$ns" -t "gekko11/insurer-login:$ns" services/insurer-login
    docker build -q --build-arg VARIANT="$ns" -t "gekko11/insurer-backend:$ns" services/insurer-backend
    docker build -q -f deploy/node.Dockerfile --build-arg VARIANT="$ns" -t "gekko11/node:$ns" .
    images+=("gekko11/insurer-auth:$ns" "gekko11/insurer-login:$ns" "gekko11/insurer-backend:$ns" "gekko11/node:$ns")
  done
  k3d image import -c "$CLUSTER" "${images[@]}"
  # 外から取ったイメージは、複数の CPU 向けの目次を持つが、手元には、この PC の CPU の分しかない。そのまま取り込むと、
  # ほかの CPU の分が見つからずに失敗するので、この PC の CPU の分だけを書き出して取り込む
  local platform tarball
  platform="linux/$(docker version --format '{{.Server.Arch}}')"
  tarball="$(mktemp -d)/external.tar"
  docker save --platform "$platform" -o "$tarball" "${external[@]}"
  k3d image import -c "$CLUSTER" "$tarball"
  rm -rf "$(dirname "$tarball")"

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

  # マニフェストに入らない値の変更も、Pod に伝える（deploy/render.ts の末尾）。値そのものは渡さない
  CLAUDE_TOKEN_SHA=$(printf %s "$token" | sha256sum | cut -d' ' -f1)
  BUNDLE_CA_SHA=$(sha256sum .secrets/spire-bundle-endpoint/tls.crt | cut -d' ' -f1)
  export CLAUDE_TOKEN_SHA BUNDLE_CA_SHA
  for ns in "${NAMESPACES[@]}"; do
    # イメージか設定が変わった Deployment だけが更新される（deploy/render.ts の末尾）
    node deploy/render.ts "$ns" | kubectl apply -f -
  done
  # Alloy は、secure と vulnerable の名前空間ができてから置く（両方の名前空間に、記録を読む権限を置くため）
  apply_and_restart_on_config_change logging deploy/k8s/logging alloy-config deployment/alloy
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
