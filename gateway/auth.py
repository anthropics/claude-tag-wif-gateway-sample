# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Token validation for the Claude Tag sample gateway.

Every check the onboarding guide lists runs here. Signature against the
issuer JWKS, exact issuer match, the registered audience, and expiry.
Any failure produces a generic 401 so responses never leak which check
failed or what the token contained.
"""

import jwt
from fastapi import HTTPException, Request

from gateway.constants import (
    AGENT_SUBJECT_PREFIX,
    ALLOWED_ALGORITHMS,
    CLAUDE_TAG_ISSUER,
)
from gateway.jwks import JWKSUnavailableError, UnknownKeyError


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="invalid token")


def _extract_bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization")
    if not authorization:
        raise _unauthorized()
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or " " in token:
        raise _unauthorized()
    return token


async def verify_request(request: Request) -> dict:
    """Validates the bearer token on a request and returns its claims."""
    token = _extract_bearer_token(request)
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise _unauthorized() from None
    # The algorithm allowlist is also enforced by the decode call below.
    # Checking the header first rejects algorithm confusion attempts
    # before any key lookup happens.
    if unverified_header.get("alg") not in ALLOWED_ALGORITHMS:
        raise _unauthorized()
    kid = unverified_header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise _unauthorized()

    try:
        signing_key = await request.app.state.jwks.get_key(kid)
    except UnknownKeyError:
        raise _unauthorized() from None
    except JWKSUnavailableError:
        # The gateway cannot verify anything without issuer keys, so it
        # fails closed with a server side status rather than blaming the
        # caller's token.
        raise HTTPException(
            status_code=503, detail="token verification unavailable"
        ) from None

    try:
        claims = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            issuer=CLAUDE_TAG_ISSUER,
            # On the wire the audience claim is a JSON array with one
            # element, which is standard JWT. The library check below
            # handles both that form and a bare string, as the guide
            # recommends, instead of comparing raw claim text.
            audience=request.app.state.config.audience,
            leeway=0,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError:
        raise _unauthorized() from None

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.startswith(AGENT_SUBJECT_PREFIX):
        raise _unauthorized()
    return claims
