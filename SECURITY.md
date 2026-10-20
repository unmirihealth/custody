# Security policy

Report a vulnerability to **security@unmiri.com**. Please do not open a
public issue for a security report.

Include what you found, the steps to reproduce it, and the version of
Custody you tested. We will acknowledge receipt within 3 business days.

Do not include real patient data in a report, in any form, even as a
reproduction example. Use synthetic data (see CONTRIBUTING.md) or
describe the issue without a concrete dataset.

## Scope

This policy covers the `custody` package and its built-in tools, policy
engine, approval broker, audit log, sandbox executor, and CLI. It does
not cover downstream MCP servers you configure Custody to proxy, or the
Docker daemon and host OS Custody runs on (see docs/threat-model.md,
"Explicitly out of scope for v0.1").
