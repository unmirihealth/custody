# The egress allowlist proxy image (docs/threat-model.md T9,
# custody.sandbox.egress_proxy). Deliberately minimal: stdlib-only
# Python, nothing else, matching sandbox.Dockerfile's "nothing extra"
# posture. Built and tagged locally
# (`docker build -f docker/egress-proxy.Dockerfile -t custody-egress-proxy:latest .`);
# not published to a registry in this release.
FROM python:3.12-alpine

COPY docker/egress_proxy_server.py /egress_proxy_server.py

EXPOSE 3128

ENTRYPOINT ["python3", "/egress_proxy_server.py"]
