# Kubernetes deployment

`k8s/` is a plain Kubernetes manifest set (no Helm chart, see "What is
NOT built" below) for running the Custody gateway as a long-running
HTTP service, instead of the stdio mode a locally-spawned agent session
uses (docs/integrations/claude-code.md).

## What this actually is

`docker/custody.Dockerfile` packages the `custody` CLI and runs:

```
custody serve --transport streamable-http --host 0.0.0.0 --port 8080 --dir /data --principal k8s-gateway
```

`mcp.run(transport="streamable-http", ...)` is built into the MCP
Python SDK Custody already depends on (`mcp>=2.3`); the only new code
here is the CLI flags (`--transport`, `--host`, `--port`) wiring up to
it. Everything else -- the policy engine, the audit log, the approval
broker, the six built-in tools -- is identical code to the stdio path,
just reached over HTTP instead of stdin/stdout.

## Quickstart against a local `kind` cluster

```bash
docker build -f docker/custody.Dockerfile -t custody-gateway:latest .
kind create cluster
kind load docker-image custody-gateway:latest
kubectl apply -k k8s/
kubectl -n custody rollout status deployment/custody-gateway
```

Or run `k8s/smoke-test.sh`, which does all of the above plus a real
MCP `initialize` handshake through the Service and a Pod-restart check
that the signing key (and therefore audit chain continuity) survives.
This is the exact script `.github/workflows/k8s-smoke.yml` runs in CI,
against a cluster GitHub Actions creates fresh on every push that
touches `k8s/`, `docker/custody.Dockerfile`, or `src/custody/`.

## The manifests

| File | What it does |
|---|---|
| `k8s/namespace.yaml` | a dedicated `custody` namespace |
| `k8s/configmap.yaml` | starter `policy.yaml`/`catalog.yaml`/`principals.yaml`, identical content to `custody init`'s own starters -- **replace this before pointing at anything real** |
| `k8s/pvc.yaml` | a 1Gi `ReadWriteOnce` PersistentVolumeClaim backing `/data/.custody/` (signing key, audit log, approvals database) |
| `k8s/deployment.yaml` | the Pod spec: non-root, read-only root filesystem, all capabilities dropped, resource limits, TCP liveness/readiness probes |
| `k8s/service.yaml` | a ClusterIP Service on port 8080 |
| `k8s/kustomization.yaml` | `kubectl apply -k k8s/` applies all five in order |

Policy files are mounted from the ConfigMap via per-key `subPath`
mounts layered onto the same `/data` directory the PVC backs, a
standard pattern for combining a ConfigMap and a PVC at one mount
point. Known limitation of `subPath` mounts: **updating the ConfigMap
does not hot-reload the file inside a running Pod**; a Deployment
restart (`kubectl rollout restart deployment/custody-gateway -n
custody`) is required after editing `k8s/configmap.yaml` and
re-applying it.

## Why one replica

`strategy: { type: Recreate }` and no `replicas` guidance above 1 are
deliberate, not an oversight. `LocalFileSink` (the audit log) and
`ApprovalStore` (SQLite) both assume one writer process with exclusive
access to their files; two Pods pointed at the same PVC would race on
`seq` numbers and hash-chain continuity, the exact failure mode
docs/threat-model.md T3 exists to detect, not something you want
self-inflicted by the deployment topology. `S3ObjectLockSink`
(docs/s3-object-lock-sink.md) does not fix this either: the race is in
computing the next `seq` and `prev_hash` sequentially, which needs one
process doing it, not in where the bytes end up. Horizontal scaling
of the gateway itself is not built; it would need a different audit
log and approval store design (a real multi-writer-safe database) that
is out of scope here.

## What is NOT built

- **No Helm chart.** Plain manifests + `kustomization.yaml` only.
  `helm` was used to run the CI workflow's cluster setup action
  (`helm/kind-action`), not to package Custody itself.
- **No Ingress / TLS termination.** The Service is `ClusterIP`; exposing
  it outside the cluster (an Ingress controller, a TLS cert, auth in
  front of it) is a deployment-specific decision left undecided here,
  same posture as the approvals UI's `127.0.0.1`-only binding in
  single-machine mode.
- **No sandbox execution inside the cluster, by default.**
  `custody.sandbox.SandboxExecutor` needs a Docker daemon
  (`docker.from_env()`); a plain Kubernetes Pod has no Docker socket.
  Without one, `shell.run` and `sql.query` resolve to `denied` (Docker
  unavailable) -- the same documented fallback as any other
  Docker-unavailable environment, not a crash. Giving a Pod Docker
  access means either mounting the host's Docker socket (a well-known
  privilege-escalation anti-pattern) or running Docker-in-Docker as a
  sidecar (real operational complexity and its own security
  tradeoffs). Deciding which, and configuring it, is left to each
  deployment; `docker/custody.Dockerfile`'s own docstring repeats this.
  `catalog.list`, `files.write`/`files.export`, and
  `approvals.status` do not need the sandbox and work normally.
