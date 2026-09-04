# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Claims to principal mapping tests."""

from tests.conftest import MAPPED_CHANNEL, UNMAPPED_SUBJECT


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
