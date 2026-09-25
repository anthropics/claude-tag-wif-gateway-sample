# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation public beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Key age limit tests for the JWKS cache.

The issuer here is a mock that can be set to fail a refresh in each way
the cache handles, and the clock is the settable one from conftest, so
the tests run offline and instantly.
"""

import asyncio

import httpx
import pytest

from gateway.jwks import JWKSCache, JWKSUnavailableError
from tests.conftest import make_es256_key, public_jwk

DISCOVERY_URL = "https://issuer.example/.well-known/openid-configuration"
JWKS_URL = "https://issuer.example/jwks"
LIMIT = 600.0
RETRY = 1.0


class MockIssuer:
    def __init__(self) -> None:
        self.mode = "ok"
        self.refresh_attempts = 0
        self._jwk = public_jwk(make_es256_key(), "k1")

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == DISCOVERY_URL:
            self.refresh_attempts += 1
        if self.mode == "http_error":
            return httpx.Response(503)
        if str(request.url) == DISCOVERY_URL:
            document = {} if self.mode == "no_jwks_uri" else {"jwks_uri": JWKS_URL}
            return httpx.Response(200, json=document)
        keys = [] if self.mode == "no_usable_keys" else [self._jwk]
        return httpx.Response(200, json={"keys": keys})


def run_with_cache(scenario, issuer, **cache_options) -> None:
    cache_options.setdefault("max_key_age_seconds", LIMIT)
    cache_options.setdefault("empty_cache_retry_interval_seconds", RETRY)

    async def main():
        async with httpx.AsyncClient(transport=httpx.MockTransport(issuer)) as client:
            await scenario(JWKSCache(client, DISCOVERY_URL, **cache_options))

    asyncio.run(main())


@pytest.mark.parametrize("failure", ["http_error", "no_jwks_uri", "no_usable_keys"])
def test_cached_keys_are_served_only_up_to_the_age_limit(clock, failure):
    issuer = MockIssuer()

    async def scenario(cache: JWKSCache):
        fetched_at = clock.now
        assert (await cache.get_key("k1")).key_id == "k1"

        issuer.mode = failure
        clock.now = fetched_at + LIMIT - RETRY
        assert (await cache.get_key("k1")).key_id == "k1"

        clock.now = fetched_at + LIMIT
        attempts_before = issuer.refresh_attempts
        results = await asyncio.gather(
            cache.get_key("never-published"),
            cache.get_key("k1"),
            cache.get_key("k1"),
            return_exceptions=True,
        )
        assert [type(result) for result in results] == [JWKSUnavailableError] * 3
        assert issuer.refresh_attempts == attempts_before + 1

        issuer.mode = "ok"
        clock.now += RETRY
        refetched_at = clock.now
        assert (await cache.get_key("k1")).key_id == "k1"

        issuer.mode = failure
        clock.now = refetched_at + LIMIT - RETRY
        assert (await cache.get_key("k1")).key_id == "k1"

    run_with_cache(scenario, issuer)


def test_age_limit_shorter_than_the_cache_ttl_still_applies(clock):
    issuer = MockIssuer()

    async def scenario(cache: JWKSCache):
        fetched_at = clock.now
        assert (await cache.get_key("k1")).key_id == "k1"
        issuer.mode = "http_error"
        clock.now = fetched_at + 99
        assert (await cache.get_key("k1")).key_id == "k1"
        clock.now = fetched_at + 100
        with pytest.raises(JWKSUnavailableError):
            await cache.get_key("k1")

    run_with_cache(scenario, issuer, cache_ttl_seconds=300, max_key_age_seconds=100)


def test_requests_queued_behind_a_slow_failed_refresh_do_not_each_retry(clock):
    issuer = MockIssuer()

    def slow_issuer(request: httpx.Request) -> httpx.Response:
        clock.now += 10
        return issuer(request)

    async def scenario(cache: JWKSCache):
        assert (await cache.get_key("k1")).key_id == "k1"
        issuer.mode = "http_error"
        clock.now += LIMIT
        attempts_before = issuer.refresh_attempts
        results = await asyncio.gather(
            *(cache.get_key("k1") for _ in range(5)), return_exceptions=True
        )
        assert [type(result) for result in results] == [JWKSUnavailableError] * 5
        assert issuer.refresh_attempts == attempts_before + 1

        clock.now += RETRY
        with pytest.raises(JWKSUnavailableError):
            await cache.get_key("k1")
        assert issuer.refresh_attempts == attempts_before + 2

    run_with_cache(scenario, slow_issuer)
