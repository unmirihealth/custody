"""A generic webhook notifier for new pending approvals: Slack-compatible
JSON payload (a `text` field Slack's Incoming Webhooks render directly;
most other webhook receivers -- Discord via a compatibility shim, a
custom endpoint -- can read the same field). Sends a link, never PHI,
same discipline as everything else that touches an approval's summary
(docs/threat-model.md T6).

This was listed alongside the CLI and the local web UI as a v0.1
approval-broker channel and was the one piece of that list not built in
the initial release; see CHANGELOG.md.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Protocol

from custody.approvals.models import PendingApproval

logger = logging.getLogger("custody.approvals.notifier")


class ApprovalNotifier(Protocol):
    """Anything that can be told about a newly pending approval. The
    broker/gateway call this best-effort: a notifier failure must never
    block or fail the approval request itself, see WebhookNotifier's
    docstring for why.
    """

    def notify(self, approval: PendingApproval, *, review_url: str | None = None) -> None: ...


class NullNotifier:
    """The default: no notifier configured, notify() is a no-op. Having
    this as a real class (rather than `None` checked everywhere) means
    the gateway always has something to call."""

    def notify(self, approval: PendingApproval, *, review_url: str | None = None) -> None:
        return


def _default_post(url: str, payload: bytes, timeout: float) -> int:
    req = urllib.request.Request(  # noqa: S310 - url is operator-configured, not user input
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - see above
        return int(resp.status)


class WebhookNotifier:
    """Posts a Slack-compatible `{"text": ...}` payload to `webhook_url`
    whenever `notify()` is called. Network failures are logged, never
    raised: a Slack outage, a typo'd URL, or a firewall should not be
    able to break approval requests, which are themselves already the
    mechanism for handling something risky. `post` is injectable so
    tests never make a real network call.
    """

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout: float = 5.0,
        post: Callable[[str, bytes, float], int] = _default_post,
    ) -> None:
        self._webhook_url = webhook_url
        self._timeout = timeout
        self._post = post

    def notify(self, approval: PendingApproval, *, review_url: str | None = None) -> None:
        link_line = f" Review: {review_url}" if review_url else ""
        text = (
            f"Custody: approval needed for `{approval.summary.tool}` "
            f"({approval.summary.data_class}), {approval.required_count} of "
            f"{approval.required_roles} needed. Approval id `{approval.id}`."
            f"{link_line}"
        )
        payload = json.dumps({"text": text}).encode("utf-8")
        try:
            status = self._post(self._webhook_url, payload, self._timeout)
            if status >= 400:
                logger.warning(
                    "approval notifier: webhook returned HTTP %s for approval %s",
                    status,
                    approval.id,
                )
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.warning(
                "approval notifier: failed to reach webhook for approval %s: %s",
                approval.id,
                exc,
            )
