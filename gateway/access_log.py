# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Authorization decision log: one JSON line per decision.

Never pass token contents, or claims from a token that did not verify,
as fields.
"""

import json
import logging

from fastapi import Request

_logger = logging.getLogger("gateway.access")


def configure() -> None:
    """Enables INFO lines; adds a stderr handler only if logging is unconfigured."""
    _logger.setLevel(logging.INFO)
    if _logger.handlers or logging.getLogger().handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.propagate = False


def record(request: Request, decision: str, **fields: str) -> None:
    entry = {
        "event": "authorization",
        "decision": decision,
        "method": request.method,
        "path": request.url.path,
        **fields,
    }
    level = logging.INFO if decision == "accepted" else logging.WARNING
    _logger.log(level, json.dumps(entry))
