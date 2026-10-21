# Egress allowlist proxy

`allow_egress=True` on its own (passed to `SandboxExecutor.run()`, or
via `shell.run`'s `egress` argument) is a plain on/off switch: the
sandboxed container joins Docker's normal bridge network, which can
reach anywhere the host can. That is the behavior docs/threat-model.md
T9 originally flagged as a residual risk, and it is still what happens
if you do nothing further.

Setting `SandboxConfig.egress_allowlist` turns the same
`allow_egress=True` into a scoped request instead: the sandboxed
container is attached to a Docker network created with `internal=True`
(Docker's own flag for "no route out of this network at all") alongside
a small forward proxy that is the *only* thing also attached to a
normal, internet-reaching network. The sandboxed container's one and
only path anywhere, allowlisted host or not, goes through that proxy.

```python
from custody.sandbox import SandboxConfig, SandboxExecutor

config = SandboxConfig(
    image="alpine:3.20",
    egress_allowlist=["pypi.org", "files.pythonhosted.org"],
)
executor = SandboxExecutor(config)
result = executor.run(["pip", "install", "duckdb"], allow_egress=True)
```

The sandboxed container gets `HTTP_PROXY` / `HTTPS_PROXY` (and lowercase
variants) pointed at the proxy automatically; most tools that respect
those environment variables need nothing else.

## What enforces the allowlist

Two layers, not one:

1. **The network itself has no route out.** `internal=True` is a
   Docker daemon-level property, not an application-level filter; even
   code that ignores `HTTP_PROXY` entirely and opens a raw socket has
   nowhere to send it, the network has no default gateway to anywhere
   but the proxy.
2. **The proxy refuses non-allowlisted hosts.** `docker/egress_proxy
   _server.py` is a small stdlib-only (no new dependency) HTTP forward
   proxy. It handles `CONNECT` (the usual case, HTTPS tunneling) by
   checking the requested host against `ALLOWED_HOSTS` before ever
   opening a connection, and plain HTTP forwarding (`GET`/`POST`/`HEAD`)
   the same way, checking the request's URL or `Host` header.
   `ALLOWED_HOSTS` entries match exactly or as an `fnmatch`-style glob
   (`*.pythonhosted.org`).

## What this does NOT do

- **Does not inspect what happens inside an allowed HTTPS connection.**
  The proxy sees the `CONNECT` target (host:port) and then just pipes
  bytes; it does not terminate TLS, so it cannot restrict a specific
  URL path on an otherwise-allowed host, or inspect request/response
  bodies.
- **Does not warn if you forget the allowlist.** An empty
  `egress_allowlist` is a silent fallback to the old unscoped
  behavior, not an error. This is the explicit remaining residual risk
  named in docs/threat-model.md T9, now opt-in rather than the only
  option.
- **Is not a hardened, widely-audited proxy implementation.** It is a
  few hundred lines of stdlib Python, built and tested for this
  project's specific use (a short-lived, per-run egress gate), not a
  general-purpose production proxy. A deployment that needs that level
  of assurance should run something like Squid with an equivalent ACL
  behind the same internal-network pattern instead of this one.

## Lifecycle

One `EgressAllowlistProxy` instance covers exactly one sandboxed run: a
fresh internal Docker network and a fresh proxy container are created
in `SandboxExecutor.run()` before the sandboxed container starts, and
torn down (container removed, network removed) after it finishes, times
out, or fails to start. Nothing is reused between runs, so one run's
allowlist can never leak into another's, at the cost of the proxy's
own startup time (typically well under a second locally) added to
every egress-allowed call.

## Building the image

```bash
docker build -f docker/egress-proxy.Dockerfile -t custody-egress-proxy:latest .
```

CI builds this image the same way it builds `custody-sandbox:duckdb`,
before running the test suite (see `.github/workflows/ci.yml`). It is
not required for `custody demo` or the quickstart, which never set
`egress_allowlist`; build it only if your own deployment configures
scoped egress.
