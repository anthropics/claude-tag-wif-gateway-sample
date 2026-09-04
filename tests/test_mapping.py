# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation public beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Claims to principal mapping tests."""

from pathlib import Path

import pytest
from gateway.mapping import AccessConfig
from tests.conftest import (
    CONTROL_SUBJECT,
    MAPPED_CHANNEL,
    ORGANIZATION_PREFIX,
    TEST_AUDIENCE,
    TEST_CONFIG_WITH_ORGANIZATION,
    TEST_SERVICES,
    UNMAPPED_SUBJECT,
)

EXAMPLE_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.example.yaml"


def test_unmapped_subject_is_forbidden(harness):
    token = harness.mint(sub=UNMAPPED_SUBJECT)
    assert harness.get("/list-services", token=token).status_code == 403


def test_channel_claim_maps_unmapped_subject(harness):
    token = harness.mint(sub=UNMAPPED_SUBJECT, slack_channel_id=MAPPED_CHANNEL)
    response = harness.get("/list-services", token=token)
    assert response.status_code == 200
    names = [service["name"] for service in response.json()["services"]]
    assert names == ["example-api"]


def test_unmapped_channel_is_forbidden(harness):
    token = harness.mint(sub=UNMAPPED_SUBJECT, slack_channel_id="C0000000000")
    assert harness.get("/list-services", token=token).status_code == 403


def test_former_channel_id_claim_name_does_not_map(harness):
    token = harness.mint(sub=UNMAPPED_SUBJECT, channel_id=MAPPED_CHANNEL)
    assert harness.get("/list-services", token=token).status_code == 403


def test_exact_subject_match_wins_over_channel(harness):
    token = harness.mint(slack_channel_id="C0000000000")
    assert harness.get("/list-services", token=token).status_code == 200


def test_example_config_maps_by_exact_subject_only():
    config = AccessConfig.load(EXAMPLE_CONFIG_PATH)
    assert config.organization_principals == {}
    assert config.subject_principals


def test_organization_prefix_maps_unpinned_agent(organization_harness):
    token = organization_harness.mint(sub=UNMAPPED_SUBJECT)
    response = organization_harness.get("/list-services", token=token)
    assert response.status_code == 200
    names = [service["name"] for service in response.json()["services"]]
    assert names == ["other-api"]


def test_exact_subject_pin_wins_over_organization_prefix(organization_harness):
    token = organization_harness.mint()
    response = organization_harness.get("/list-services", token=token)
    assert response.status_code == 200
    names = [service["name"] for service in response.json()["services"]]
    assert names == ["example-api"]


def test_organization_prefix_wins_over_channel(organization_harness):
    token = organization_harness.mint(
        sub=UNMAPPED_SUBJECT, slack_channel_id=MAPPED_CHANNEL
    )
    response = organization_harness.get("/list-services", token=token)
    assert response.status_code == 200
    names = [service["name"] for service in response.json()["services"]]
    assert names == ["other-api"]


def test_organization_prefix_never_matches_the_control_agent(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
audience: "{TEST_AUDIENCE}"
organization_principals:
  - subject_prefix: "{ORGANIZATION_PREFIX}"
    principal: "organization-agent"
    allowed_services: ["other-api"]
{TEST_SERVICES}"""
    )
    config = AccessConfig.load(str(config_path))
    organization_agent = config.resolve_principal({"sub": UNMAPPED_SUBJECT})
    assert organization_agent.name == "organization-agent"
    assert config.resolve_principal({"sub": CONTROL_SUBJECT}) is None


def test_pinned_control_subject_keeps_no_services(organization_harness):
    token = organization_harness.mint(sub=CONTROL_SUBJECT)
    headers = {"Authorization": f"Bearer {token}"}
    assert organization_harness.client.post("/", headers=headers).status_code == 200
    response = organization_harness.get("/list-services", token=token)
    assert response.json() == {"services": []}


@pytest.mark.parametrize(
    "subject",
    [
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE0/agent/cagt_0000000000000000001EXAMPLE",
        "wimse://identity.anthropic.com/org/org_1111111111111111111EXAMPLE/agent/cagt_0000000000000000001EXAMPLE",
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/agent/",
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/agent/cagt_0000000000000000001EXAMPLE/extra",
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/agents/cagt_0000000000000000001EXAMPLE",
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/AGENT/cagt_0000000000000000001EXAMPLE",
    ],
)
def test_subjects_outside_the_organization_prefix_are_forbidden(
    organization_harness, subject
):
    token = organization_harness.mint(sub=subject)
    assert organization_harness.get("/list-services", token=token).status_code == 403


@pytest.mark.parametrize(
    "subject_prefix",
    [
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE",
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/",
        "wimse://identity.anthropic.com/org/",
        "wimse://identity.anthropic.com/org//agent/",
        "wimse://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/agent/cagt_0000000000000000000EXAMPLE",
        "wimse://identity.anthropic.com/org/a/b/agent/",
        "wimse://example.com/org/org_0000000000000000000EXAMPLE/agent/",
        "https://identity.anthropic.com/org/org_0000000000000000000EXAMPLE/agent/",
        "",
    ],
)
def test_config_rejects_incomplete_subject_prefix(tmp_path, subject_prefix):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        TEST_CONFIG_WITH_ORGANIZATION.replace(
            f'subject_prefix: "{ORGANIZATION_PREFIX}"',
            f'subject_prefix: "{subject_prefix}"',
        )
    )
    with pytest.raises(ValueError):
        AccessConfig.load(str(config_path))
