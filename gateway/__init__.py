# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation public beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

__all__ = ["create_app"]

from gateway.main import create_app
