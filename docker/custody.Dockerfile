# The Custody gateway's own server image, for the Kubernetes
# Deployment in k8s/ (see docs/kubernetes.md). Runs `custody serve
# --transport streamable-http --host 0.0.0.0`, the HTTP mode a
# Service/Ingress can route to, as opposed to the stdio mode used for
# a locally-spawned agent session (docs/integrations/claude-code.md).
#
# IMPORTANT: this image does NOT include a Docker daemon, and the
# sandbox executor (custody/sandbox/executor.py) needs one to run
# shell.run / sql.query. Inside a plain Kubernetes Pod there is no
# Docker socket by default; mounting the host's (a known privilege-
# escalation anti-pattern) or running Docker-in-Docker as a sidecar
# (real complexity, its own security tradeoffs) is a deliberate
# decision left to each deployment, not decided here. Without one of
# those, shell.run and sql.query resolve to `denied` (Docker
# unavailable), the same documented behavior as any other
# Docker-unavailable environment -- see docs/kubernetes.md for what
# that means for this deployment's actual scope.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Runs as a fixed non-root uid:gid, not root -- Kubernetes manifests in
# k8s/ additionally set runAsNonRoot/readOnlyRootFilesystem at the Pod
# level, this is the matching image-level default should someone run
# the image outside those manifests.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin custody
USER 10001:10001

EXPOSE 8080

# ENTRYPOINT is fixed; CMD supplies the rest as defaults a Kubernetes
# Deployment's `args:` overrides (see k8s/deployment.yaml, which sets
# --dir and --principal explicitly rather than relying on these).
ENTRYPOINT ["custody", "serve"]
CMD ["--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8080", "--dir", "/data", "--principal", "k8s-gateway"]
