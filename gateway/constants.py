# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation public beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Shared constants for the Claude Tag sample gateway."""

# The issuer accepted when neither CLAUDE_TAG_ISSUERS nor CLAUDE_TAG_ISSUER
# is set in the environment. A token's iss claim must equal an accepted
# issuer exactly.
CLAUDE_TAG_ISSUER = "https://identity.anthropic.com/agents"

# Every accepted issuer publishes a discovery document at this path under
# its URL. The gateway reads the jwks_uri field from that document and
# fetches the signing keys it names, keeping one key set per issuer.
OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration"
# The default issuer's discovery document, for callers that build a
# single key cache themselves.
OIDC_DISCOVERY_URL = CLAUDE_TAG_ISSUER + OIDC_DISCOVERY_PATH

# Claude Tag tokens are signed with ES256. Accepting only this algorithm
# prevents algorithm confusion attacks.
ALLOWED_ALGORITHMS = ["ES256"]

# Scheme of every Claude Tag subject: the Workload Identifier URI form
# defined by the IETF WIMSE working group (draft-ietf-wimse-identifier).
AGENT_SUBJECT_PREFIX = "wimse://"

# Every subject has the form
# wimse://identity.anthropic.com/org/<organization id>/agent/<agent id>.
# An organization's subject prefix is everything up to and including
# "/agent/".
ORGANIZATION_SUBJECT_PREFIX = AGENT_SUBJECT_PREFIX + "identity.anthropic.com/org/"
AGENT_PATH_SEGMENT = "/agent/"

# The reserved agent id the registration test mints its control token
# for, the same in every organization. It is authorized only through an
# exact subject pin, never through an organization prefix.
REGISTRATION_TEST_AGENT_ID = "cagt_01YcVfxkQb6JRzqk5kF2tNLh"
