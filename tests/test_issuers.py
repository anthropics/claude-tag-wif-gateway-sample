# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Accepted issuer list and per issuer key selection tests.

Each gateway here is built through create_app's own environment and key
cache path, so the tests cover how a deployment reads CLAUDE_TAG_ISSUERS
and not only the verification code behind it.
"""

import json
import time
from dataclasses import dataclass, field

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from gateway.auth import accepted_issuers
from gateway.constants import CLAUDE_TAG_ISSUER, OIDC_DISCOVERY_PATH
from gateway.jwks import JWKSCache
from gateway.main import create_app
from tests.conftest import TEST_CONFIG, GatewayHarness, make_es256_key, public_jwk

OLD_ISSUER = "https://identity.anthropic.com/claude-tag"
NEW_ISSUER = "https://identity.anthropic.com/agents"
OTHER_ISSUER = "https://identity.example.com/agents"
SHARED_KID = "rotation-2026-09"


@dataclass
class Issuer:
    url: str
    kid: str = SHARED_KID
    key: object = field(default_factory=make_es256_key)
    reachable: bool = True


@dataclass
class IssuerHarness(GatewayHarness):
    issuers: dict[str, Issuer] = field(default_factory=dict)
    fetched_urls: list = field(default_factory=list)

    def mint_for(self, issuer_url: str, signed_by: str | None = None, **claims):
        signer = self.issuers[signed_by or issuer_url]
        return self.mint(
            key=signer.key, kid=signer.kid, **{"iss": issuer_url, **claims}
        )


@pytest.fixture
def build_gateway(tmp_path, monkeypatch):
    """Returns a factory: build_gateway(env, *issuers) yields a harness.

    env is the CLAUDE_TAG_ISSUERS value, or None to leave it unset. Every
    Issuer passed serves a discovery document and a key set, whether or
    not the gateway accepts it.
    """
    monkeypatch.delenv("CLAUDE_TAG_ISSUERS", raising=False)
    monkeypatch.delenv("CLAUDE_TAG_ISSUER", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(TEST_CONFIG)
    clients = []

    def factory(env: str | None, *issuers: Issuer) -> IssuerHarness:
        if env is not None:
            monkeypatch.setenv("CLAUDE_TAG_ISSUERS", env)
        served = {issuer.url: issuer for issuer in issuers}
        fetched_urls = []

        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            fetched_urls.append(url)
            for issuer in served.values():
                if not issuer.reachable:
                    continue
                if url == issuer.url + OIDC_DISCOVERY_PATH:
                    return httpx.Response(200, json={"jwks_uri": issuer.url + "/jwks"})
                if url == issuer.url + "/jwks":
                    return httpx.Response(
                        200, json={"keys": [public_jwk(issuer.key, issuer.kid)]}
                    )
            return httpx.Response(503)

        http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        clients.append(http_client)
        app = create_app(str(config_path), http_client=http_client)
        client = TestClient(app, backend="asyncio")
        client.__enter__()
        clients.append(client)
        return IssuerHarness(
            client=client,
            signing_key=None,
            jwks_state={},
            issuers=served,
            fetched_urls=fetched_urls,
        )

    yield factory
    for client in reversed(clients):
        if isinstance(client, TestClient):
            client.__exit__(None, None, None)


def test_default_accepts_only_the_agents_issuer(build_gateway):
    gateway = build_gateway(None, Issuer(NEW_ISSUER), Issuer(OLD_ISSUER))
    assert CLAUDE_TAG_ISSUER == NEW_ISSUER
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER)).status_code == 200
    assert gateway.get("/", gateway.mint_for(OLD_ISSUER)).status_code == 401


def test_explicit_single_issuer_replaces_the_default(build_gateway):
    gateway = build_gateway(OLD_ISSUER, Issuer(OLD_ISSUER), Issuer(NEW_ISSUER))
    assert gateway.get("/", gateway.mint_for(OLD_ISSUER)).status_code == 200
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER)).status_code == 401


def test_singular_variable_sets_one_issuer(build_gateway, monkeypatch):
    monkeypatch.setenv("CLAUDE_TAG_ISSUER", OLD_ISSUER)
    gateway = build_gateway(None, Issuer(OLD_ISSUER), Issuer(NEW_ISSUER))
    assert gateway.get("/", gateway.mint_for(OLD_ISSUER)).status_code == 200
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER)).status_code == 401


def test_listed_issuers_each_verify_with_their_own_keys(build_gateway):
    gateway = build_gateway(
        f"{OLD_ISSUER},{NEW_ISSUER}", Issuer(OLD_ISSUER), Issuer(NEW_ISSUER)
    )
    assert gateway.get("/", gateway.mint_for(OLD_ISSUER)).status_code == 200
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER)).status_code == 200
    response = gateway.get("/list-services", gateway.mint_for(NEW_ISSUER))
    assert [s["name"] for s in response.json()["services"]] == ["example-api"]


def test_token_signed_by_the_other_issuers_key_is_rejected(build_gateway):
    # Both issuers publish the same key id, so the only thing that can
    # refuse the token is the signature check against the named issuer's
    # own key.
    gateway = build_gateway(
        f"{OLD_ISSUER},{NEW_ISSUER}", Issuer(OLD_ISSUER), Issuer(NEW_ISSUER)
    )
    crossed = gateway.mint_for(NEW_ISSUER, signed_by=OLD_ISSUER)
    assert gateway.get("/", crossed).status_code == 401
    crossed = gateway.mint_for(OLD_ISSUER, signed_by=NEW_ISSUER)
    assert gateway.get("/", crossed).status_code == 401


def test_other_issuers_key_id_is_unknown_to_the_named_issuer(build_gateway):
    gateway = build_gateway(
        f"{OLD_ISSUER},{NEW_ISSUER}",
        Issuer(OLD_ISSUER, kid="old-key"),
        Issuer(NEW_ISSUER, kid="new-key"),
    )
    crossed = gateway.mint_for(NEW_ISSUER, signed_by=OLD_ISSUER)
    assert gateway.get("/", crossed).status_code == 401
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER)).status_code == 200


def test_unlisted_issuer_is_rejected_before_any_key_lookup(build_gateway):
    gateway = build_gateway(
        f"{OLD_ISSUER},{NEW_ISSUER}",
        Issuer(OLD_ISSUER),
        Issuer(NEW_ISSUER),
        Issuer(OTHER_ISSUER),
    )
    assert gateway.get("/", gateway.mint_for(OTHER_ISSUER)).status_code == 401
    for near_miss in (
        NEW_ISSUER + "/",
        NEW_ISSUER + "x",
        NEW_ISSUER.upper(),
        "https://identity.anthropic.com",
        "agents",
    ):
        token = gateway.mint_for(near_miss, signed_by=NEW_ISSUER)
        assert gateway.get("/", token).status_code == 401
    assert gateway.fetched_urls == []


def test_missing_or_malformed_issuer_claim_is_rejected(build_gateway):
    gateway = build_gateway(None, Issuer(NEW_ISSUER))
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER, iss=None)).status_code == 401
    # PyJWT refuses to encode a non string iss, so the token is signed
    # from raw bytes.
    issuer = gateway.issuers[NEW_ISSUER]
    payload = json.dumps(
        {"iss": [NEW_ISSUER], "aud": ["x"], "sub": "wimse://x", "exp": time.time() + 60}
    ).encode()
    listed_not_string = jwt.api_jws.PyJWS().encode(
        payload, issuer.key, algorithm="ES256", headers={"kid": issuer.kid}
    )
    assert gateway.get("/", listed_not_string).status_code == 401
    assert gateway.fetched_urls == []


def test_unreachable_issuer_fails_closed_for_its_own_tokens_only(build_gateway):
    gateway = build_gateway(
        f"{OLD_ISSUER},{NEW_ISSUER}",
        Issuer(OLD_ISSUER, reachable=False),
        Issuer(NEW_ISSUER),
    )
    assert gateway.get("/", gateway.mint_for(NEW_ISSUER)).status_code == 200
    assert gateway.get("/", gateway.mint_for(OLD_ISSUER)).status_code == 503


def test_single_injected_cache_serves_the_one_accepted_issuer(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_TAG_ISSUERS", raising=False)
    monkeypatch.delenv("CLAUDE_TAG_ISSUER", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(TEST_CONFIG)
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(503))
    )
    cache = JWKSCache(http_client, OLD_ISSUER + OIDC_DISCOVERY_PATH)

    with TestClient(
        create_app(str(config_path), http_client=http_client, jwks_cache=cache)
    ) as client:
        assert list(client.app.state.jwks) == [NEW_ISSUER]
    monkeypatch.setenv("CLAUDE_TAG_ISSUER", OLD_ISSUER)
    with TestClient(
        create_app(str(config_path), http_client=http_client, jwks_cache=cache)
    ) as client:
        assert client.app.state.jwks == {OLD_ISSUER: cache}
    monkeypatch.setenv("CLAUDE_TAG_ISSUERS", f"{OLD_ISSUER},{NEW_ISSUER}")
    with pytest.raises(ValueError):
        create_app(str(config_path), http_client=http_client, jwks_cache=cache)


def test_issuer_list_parsing(monkeypatch):
    monkeypatch.delenv("CLAUDE_TAG_ISSUER", raising=False)
    monkeypatch.delenv("CLAUDE_TAG_ISSUERS", raising=False)
    assert accepted_issuers() == (CLAUDE_TAG_ISSUER,)
    monkeypatch.setenv("CLAUDE_TAG_ISSUERS", "")
    assert accepted_issuers() == (CLAUDE_TAG_ISSUER,)
    monkeypatch.setenv("CLAUDE_TAG_ISSUERS", f" {OLD_ISSUER} , {NEW_ISSUER} ,")
    assert accepted_issuers() == (OLD_ISSUER, NEW_ISSUER)
    monkeypatch.setenv("CLAUDE_TAG_ISSUER", OTHER_ISSUER)
    assert accepted_issuers() == (OLD_ISSUER, NEW_ISSUER)
    monkeypatch.setenv("CLAUDE_TAG_ISSUERS", "")
    assert accepted_issuers() == (OTHER_ISSUER,)


@pytest.mark.parametrize(
    "value",
    [
        NEW_ISSUER + "/",
        "http://identity.anthropic.com/agents",
        f"{NEW_ISSUER},{NEW_ISSUER}",
        "identity.anthropic.com/agents",
        " , ",
    ],
)
def test_malformed_issuer_list_stops_startup(tmp_path, monkeypatch, value):
    monkeypatch.setenv("CLAUDE_TAG_ISSUERS", value)
    with pytest.raises(ValueError):
        accepted_issuers()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(TEST_CONFIG)
    with pytest.raises(ValueError):
        create_app(str(config_path))
