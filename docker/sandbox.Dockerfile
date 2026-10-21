# The image custody.sandbox.SandboxExecutor uses for sql.query. Deliberately
# minimal: Python plus DuckDB, nothing else. Built and tagged locally
# (`docker build -f docker/sandbox.Dockerfile -t custody-sandbox:duckdb .`);
# not published to a registry in v0.1, see docs/demo.md for the exact build
# step the demo runs before it starts.
FROM python:3.15-alpine

RUN pip install --no-cache-dir duckdb==1.1.3

# No ENTRYPOINT/CMD: custody.sandbox always supplies the full command
# (python3 -c "...") itself, see custody/tools/sql.py.
