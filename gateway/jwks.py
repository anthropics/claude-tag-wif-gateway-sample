# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""OIDC discovery and JWKS caching for the Claude Tag sample gateway.

The gateway resolves signing keys the way the onboarding guide describes.
It fetches the discovery document, follows the jwks_uri field, and caches
the returned keys. When a token names a key id that is not in the cache,
the cache refreshes once before rejecting, which is how key rotation is
absorbed without a restart.
"""

import asyncio
import time

import httpx
import jwt


class JWKSUnavailableError(Exception):
    """Raised when signing keys cannot be fetched and none are cached."""


class UnknownKeyError(Exception):
    """Raised when a key id is not in the key set even after a refresh."""


class JWKSCache:
    def __init__(
        self,
        http_client: httpx.AsyncClient,
        discovery_url: str,
        cache_ttl_seconds: float = 300.0,
        min_refresh_interval_seconds: float = 30.0,
        empty_cache_retry_interval_seconds: float = 1.0,
    ) -> None:
        self._http = http_client
        self._discovery_url = discovery_url
        self._cache_ttl = cache_ttl_seconds
        self._min_refresh_interval = min_refresh_interval_seconds
        self._empty_cache_retry_interval = empty_cache_retry_interval_seconds
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float = 0.0
        self._last_attempt_at: float = float("-inf")
        self._refresh_lock = asyncio.Lock()

    def _fresh_key(self, kid: str) -> jwt.PyJWK | None:
        cache_fresh = (
            self._keys and (time.monotonic() - self._fetched_at) < self._cache_ttl
        )
        if cache_fresh and kid in self._keys:
            return self._keys[kid]
        return None

    async def get_key(self, kid: str) -> jwt.PyJWK:
        key = self._fresh_key(kid)
        if key is not None:
            return key
        # The key id is unknown or the cache is stale. Refresh unless a
        # refresh ran very recently, which bounds how hard a flood of bad
        # tokens can make the gateway hit the issuer. An empty cache only
        # shortens that wait, it never removes it, so unauthenticated
        # traffic cannot drive unbounded issuer fetches while the first
        # fetch is failing. The lock keeps concurrent requests from
        # stampeding the issuer with one refresh each.
        async with self._refresh_lock:
            key = self._fresh_key(kid)
            if key is None:
                now = time.monotonic()
                min_interval = (
                    self._min_refresh_interval
                    if self._keys
                    else self._empty_cache_retry_interval
                )
                if now - self._last_attempt_at >= min_interval:
                    await self._refresh()
                elif not self._keys:
                    raise JWKSUnavailableError(
                        "signing keys are not available yet"
                    )
        if kid in self._keys:
            return self._keys[kid]
        raise UnknownKeyError("token key id is not in the issuer key set")

    async def _refresh(self) -> None:
        self._last_attempt_at = time.monotonic()
        try:
            discovery_response = await self._http.get(self._discovery_url)
            discovery_response.raise_for_status()
            discovery_document = discovery_response.json()
            jwks_uri = (
                discovery_document.get("jwks_uri")
                if isinstance(discovery_document, dict)
                else None
            )
            if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
                raise JWKSUnavailableError("discovery document has no usable jwks_uri")
            jwks_response = await self._http.get(jwks_uri)
            jwks_response.raise_for_status()
            jwks_document = jwks_response.json()
            raw_keys = (
                jwks_document.get("keys", []) if isinstance(jwks_document, dict) else []
            )
            if not isinstance(raw_keys, list):
                raw_keys = []
        except JWKSUnavailableError:
            if not self._keys:
                raise
            return
        except (httpx.HTTPError, ValueError) as exc:
            # A failed refresh keeps serving previously cached keys until
            # they age out. With nothing cached the gateway fails closed.
            if not self._keys:
                raise JWKSUnavailableError(
                    "could not fetch issuer signing keys"
                ) from exc
            return
        keys: dict[str, jwt.PyJWK] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                continue
            try:
                parsed = jwt.PyJWK.from_dict(raw_key)
            except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError):
                continue
            if raw_key.get("kid"):
                keys[raw_key["kid"]] = parsed
        if not keys:
            if not self._keys:
                raise JWKSUnavailableError("issuer key set contains no usable keys")
            return
        self._keys = keys
        self._fetched_at = time.monotonic()
