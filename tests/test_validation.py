# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Token validation tests mirroring the onboarding guide's verify list.

The guide says to verify that the endpoint rejects a token with a wrong
audience, a bad signature, or an expired timestamp, and accepts a valid
token against a local JWKS. Each case below is one of those checks plus
the adjacent failure modes a validator must also close.
"""

import time

from tests.conftest import CLAUDE_TAG_ISSUER, TEST_KID, make_es256_key, public_jwk


def test_accepts_valid_token(harness):
    response = harness.get("/list-services", token=harness.mint())
    assert response.status_code == 200
    names = [service["name"] for service in response.json()["services"]]
    assert names == ["example-api"]


def test_rejects_missing_authorization(harness):
    assert harness.get("/list-services").status_code == 401


def test_rejects_non_bearer_scheme(harness):
    response = harness.get("/list-services", headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_rejects_wrong_audience(harness):
    token = harness.mint(aud=["some-other-audience"])
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_bad_signature(harness):
    wrong_key = make_es256_key()
    token = harness.mint(key=wrong_key)
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_expired_token(harness):
    now = int(time.time())
    token = harness.mint(iat=now - 700, exp=now - 60)
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_wrong_issuer(harness):
    token = harness.mint(iss="https://identity.example.com/other")
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_alg_none(harness):
    import jwt as pyjwt

    token = pyjwt.encode(
        {
            "iss": CLAUDE_TAG_ISSUER,
            "sub": "wimse://x",
            "aud": ["test-gateway-audience"],
            "exp": int(time.time()) + 600,
        },
        None,
        algorithm="none",
        headers={"kid": TEST_KID},
    )
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_missing_kid(harness):
    token = harness.mint(kid=None)
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_unknown_kid(harness):
    token = harness.mint(kid="key-that-never-existed")
    assert harness.get("/list-services", token=token).status_code == 401


def test_malformed_key_in_jwks_is_skipped(harness):
    harness.jwks_state["keys"].insert(
        0, {"kty": "EC", "crv": "P-256", "kid": "broken-key", "x": "!!", "y": "!!"}
    )
    assert harness.get("/list-services", token=harness.mint()).status_code == 200


def test_refresh_on_unknown_kid_absorbs_rotation(harness):
    rotated_key = make_es256_key()
    harness.jwks_state["keys"].append(public_jwk(rotated_key, "test-key-2"))
    token = harness.mint(key=rotated_key, kid="test-key-2")
    assert harness.get("/list-services", token=token).status_code == 200


def test_rejects_garbage_token(harness):
    assert harness.get("/list-services", token="not.a.jwt").status_code == 401


def test_rejects_missing_subject(harness):
    token = harness.mint(sub=None)
    assert harness.get("/list-services", token=token).status_code == 401


def test_rejects_non_agent_subject(harness):
    token = harness.mint(sub="urn:example:not-an-agent")
    assert harness.get("/list-services", token=token).status_code == 401


def test_empty_key_cache_refresh_is_rate_limited():
    # Before the first successful JWKS fetch, repeated bad tokens must
    # not translate into one issuer fetch each; the retry interval
    # applies even when the cache is empty.
    import asyncio

    import httpx

    from gateway.constants import OIDC_DISCOVERY_URL
    from gateway.jwks import JWKSCache, JWKSUnavailableError

    fetch_attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetch_attempts.append(str(request.url))
        return httpx.Response(503)

    async def scenario():
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        cache = JWKSCache(client, OIDC_DISCOVERY_URL)
        for _ in range(5):
            try:
                await cache.get_key(TEST_KID)
            except JWKSUnavailableError:
                pass
        await client.aclose()

    asyncio.run(scenario())
    assert len(fetch_attempts) == 1
