# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Shared constants for the Claude Tag sample gateway."""

# Tokens whose iss claim differs from this exact value are rejected.
CLAUDE_TAG_ISSUER = "https://identity.anthropic.com/claude-tag"

# The gateway reads the jwks_uri field from this discovery document and
# fetches the signing keys it names.
OIDC_DISCOVERY_URL = CLAUDE_TAG_ISSUER + "/.well-known/openid-configuration"

# Claude Tag tokens are signed with ES256. Accepting only this algorithm
# prevents algorithm confusion attacks.
ALLOWED_ALGORITHMS = ["ES256"]

# Scheme of every Claude Tag subject: the Workload Identifier URI form
# defined by the IETF WIMSE working group (draft-ietf-wimse-identifier).
AGENT_SUBJECT_PREFIX = "wimse://"
