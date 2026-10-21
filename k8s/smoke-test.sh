#!/usr/bin/env bash
# End-to-end verification against a real kind cluster: build the
# image, load it, apply every manifest in k8s/, wait for the rollout,
# then run an actual MCP `initialize` handshake through the Service
# (not just a port-open check) from a throwaway in-cluster Pod. Exits
# non-zero on any failure. Run locally with a `kind` context already
# active, or see .github/workflows/k8s-smoke.yml for how CI runs this
# same script against a cluster it creates itself.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> building the gateway image"
docker build -f docker/custody.Dockerfile -t custody-gateway:latest .

echo "==> loading the image into the kind cluster"
kind load docker-image custody-gateway:latest --name "${KIND_CLUSTER_NAME:-kind}"

echo "==> applying k8s/"
kubectl apply -k k8s/

echo "==> waiting for the rollout"
kubectl -n custody rollout status deployment/custody-gateway --timeout=120s

echo "==> confirming the signing key survives a Pod restart (PVC persistence)"
before=$(kubectl -n custody exec deployment/custody-gateway -- cat /data/.custody/signing_key.pem)
kubectl -n custody delete pod -l app=custody-gateway
kubectl -n custody rollout status deployment/custody-gateway --timeout=120s
after=$(kubectl -n custody exec deployment/custody-gateway -- cat /data/.custody/signing_key.pem)
if [ "$before" != "$after" ]; then
  echo "FAIL: signing key changed across a Pod restart; PVC persistence is broken"
  exit 1
fi

echo "==> running a real MCP initialize handshake through the Service"
kubectl -n custody run mcp-smoke-test --restart=Never --image=curlimages/curl:latest \
  --command -- sleep 60
trap 'kubectl -n custody delete pod mcp-smoke-test --ignore-not-found' EXIT
kubectl -n custody wait --for=condition=Ready pod/mcp-smoke-test --timeout=30s

response=$(kubectl -n custody exec mcp-smoke-test -- curl -s -X POST http://custody-gateway:8080/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2026-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}},"id":1}')

if ! echo "$response" | grep -q '"serverInfo":{"name":"Custody"'; then
  echo "FAIL: did not get a Custody MCP initialize response. Got:"
  echo "$response"
  exit 1
fi

echo "==> OK: pod running, PVC persistence confirmed, MCP handshake succeeded through the Service"
