# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation public beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Test harness for the Claude Tag sample gateway.

The harness generates throwaway ES256 keys locally and serves them from
a mocked JWKS endpoint, so every verify step from the documentation
can be exercised with no network access and no dependency on Anthropic
infrastructure.
"""

import base64
import time
from dataclasses import dataclass, field

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from gateway.constants import CLAUDE_TAG_ISSUER, OIDC_DISCOVERY_URL
from gateway.jwks import JWKSCache
from gateway.main import create_app

TEST_AUDIENCE = "test-gateway-audience"
TEST_KID = "test-key-1"
TEST_JWKS_URL = "https://identity.anthropic.com/agents/test-jwks"
TEST_UPSTREAM = "https://api.example.test"
TEST_CREDENTIAL = "test-downstream-credential"

# These IDs are deliberately implausible example values that will not
# match any real organization or agent.
ORGANIZATION_PREFIX = "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/agent/"
MAPPED_SUBJECT = ORGANIZATION_PREFIX + "cagt_0000000000000000000EXAMPLE"
UNMAPPED_SUBJECT = ORGANIZATION_PREFIX + "cagt_0000000000000000001EXAMPLE"
CONTROL_SUBJECT = ORGANIZATION_PREFIX + "cagt_01YcVfxkQb6JRzqk5kF2tNLh"
MAPPED_CHANNEL = "C0123456789"

TEST_SERVICES = f"""
services:
  example-api:
    description: "Example downstream API for tests."
    upstream_base_url: "{TEST_UPSTREAM}"
    credential_env: "EXAMPLE_API_TOKEN"
  other-api:
    description: "A service the test agent is not allowed to use."
    upstream_base_url: "{TEST_UPSTREAM}"
    credential_env: "OTHER_API_TOKEN"
"""

TEST_CONFIG = f"""
audience: "{TEST_AUDIENCE}"
principals:
  - subject: "{MAPPED_SUBJECT}"
    principal: "test-agent"
    allowed_services: ["example-api"]
channel_principals:
  - channel_id: "{MAPPED_CHANNEL}"
    principal: "channel-agent"
    allowed_services: ["example-api"]
{TEST_SERVICES}"""

TEST_CONFIG_WITH_ORGANIZATION = f"""
audience: "{TEST_AUDIENCE}"
principals:
  - subject: "{MAPPED_SUBJECT}"
    principal: "test-agent"
    allowed_services: ["example-api"]
  - subject: "{CONTROL_SUBJECT}"
    principal: "registration-test-control"
    allowed_services: []
organization_principals:
  - subject_prefix: "{ORGANIZATION_PREFIX}"
    principal: "organization-agent"
    allowed_services: ["other-api"]
channel_principals:
  - channel_id: "{MAPPED_CHANNEL}"
    principal: "channel-agent"
    allowed_services: ["example-api"]
{TEST_SERVICES}"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_es256_key():
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(private_key, kid: str) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


@dataclass
class GatewayHarness:
    client: TestClient
    signing_key: object
    jwks_state: dict
    upstream_requests: list = field(default_factory=list)

    def mint(self, key=None, kid=TEST_KID, alg="ES256", **claim_overrides) -> str:
        now = int(time.time())
        claims = {
            "iss": CLAUDE_TAG_ISSUER,
            "aud": [TEST_AUDIENCE],
            "sub": MAPPED_SUBJECT,
            "iat": now,
            "exp": now + 600,
        }
        for name, value in claim_overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        headers = {"kid": kid} if kid is not None else None
        return jwt.encode(
            claims,
            key if key is not None else self.signing_key,
            algorithm=alg,
            headers=headers,
        )

    def get(self, path: str, token: str | None = None, headers: dict | None = None):
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        return self.client.get(path, headers=request_headers)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    yield from _run_harness(tmp_path, monkeypatch, TEST_CONFIG)


@pytest.fixture
def organization_harness(tmp_path, monkeypatch):
    yield from _run_harness(tmp_path, monkeypatch, TEST_CONFIG_WITH_ORGANIZATION)


def _run_harness(tmp_path, monkeypatch, config_text):
    monkeypatch.setenv("EXAMPLE_API_TOKEN", TEST_CREDENTIAL)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(config_text)

    signing_key = make_es256_key()
    jwks_state = {"keys": [public_jwk(signing_key, TEST_KID)]}
    upstream_requests = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url).split("?")[0]
        if url == OIDC_DISCOVERY_URL:
            return httpx.Response(200, json={"jwks_uri": TEST_JWKS_URL})
        if url == TEST_JWKS_URL:
            return httpx.Response(200, json={"keys": jwks_state["keys"]})
        if url.startswith(TEST_UPSTREAM):
            upstream_requests.append(request)
            response_headers = (
                {"set-cookie": "upstream-session=leaked; Path=/"}
                if "set-cookie" in url
                else {}
            )
            return httpx.Response(
                200, json={"upstream": "ok"}, headers=response_headers
            )
        return httpx.Response(404)

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))
    jwks_cache = JWKSCache(
        http_client, OIDC_DISCOVERY_URL, min_refresh_interval_seconds=0
    )
    app = create_app(
        str(config_path),
        http_client=http_client,
        jwks_cache={CLAUDE_TAG_ISSUER: jwks_cache},
    )
    # backend= is pinned explicitly: asyncio is the library default, and
    # the right choice over trio here because the gateway uses asyncio
    # primitives (asyncio.Lock in the JWKS cache).
    with TestClient(app, backend="asyncio") as client:
        yield GatewayHarness(
            client=client,
            signing_key=signing_key,
            jwks_state=jwks_state,
            upstream_requests=upstream_requests,
        )
