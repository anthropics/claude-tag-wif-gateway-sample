# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Authorization decision log tests."""

import json
import logging
import sys
import time

import pytest
from gateway import access_log
from tests.conftest import MAPPED_SUBJECT, UNMAPPED_SUBJECT

LOGGER_NAME = "gateway.access"


@pytest.fixture
def decisions(caplog):
    def read():
        entries = []
        for record in caplog.records:
            if record.name != LOGGER_NAME:
                continue
            assert "\n" not in record.getMessage()
            entries.append((record.levelno, json.loads(record.getMessage())))
        return entries

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        yield read


def test_unmapped_subject_is_logged_with_its_subject(harness, decisions):
    token = harness.mint(sub=UNMAPPED_SUBJECT)
    assert harness.get("/list-services", token=token).status_code == 403
    assert decisions() == [
        (
            logging.WARNING,
            {
                "event": "authorization",
                "decision": "rejected",
                "method": "GET",
                "path": "/list-services",
                "reason": "unmapped_subject",
                "subject": UNMAPPED_SUBJECT,
            },
        )
    ]


def test_accepted_request_is_logged_with_subject_and_principal(harness, decisions):
    token = harness.mint()
    assert harness.get("/list-services", token=token).status_code == 200
    assert decisions() == [
        (
            logging.INFO,
            {
                "event": "authorization",
                "decision": "accepted",
                "method": "GET",
                "path": "/list-services",
                "subject": MAPPED_SUBJECT,
                "principal": "test-agent",
            },
        )
    ]


def test_invalid_token_is_logged_without_its_claims(harness, decisions, caplog):
    token = harness.mint(sub=UNMAPPED_SUBJECT, exp=int(time.time()) - 60)
    assert harness.get("/list-services", token=token).status_code == 401
    [(level, entry)] = decisions()
    assert level == logging.WARNING
    assert entry["decision"] == "rejected"
    assert entry["reason"] == "invalid_token"
    assert "subject" not in entry
    assert UNMAPPED_SUBJECT not in caplog.text


def test_service_denial_is_logged(harness, decisions):
    token = harness.mint()
    assert harness.get("/services/other-api/v1/things", token=token).status_code == 403
    [(_, accepted), (level, denied)] = decisions()
    assert accepted["decision"] == "accepted"
    assert level == logging.WARNING
    assert denied["decision"] == "rejected"
    assert denied["reason"] == "service_not_allowed"
    assert denied["subject"] == MAPPED_SUBJECT
    assert denied["principal"] == "test-agent"
    assert denied["service"] == "other-api"


def test_log_never_contains_the_token(harness, decisions, caplog):
    tokens = [harness.mint(), harness.mint(sub=UNMAPPED_SUBJECT), "not.a.token"]
    for token in tokens:
        harness.get("/list-services", token=token)
    assert len(decisions()) == 3
    for token in tokens:
        assert token not in caplog.text


def test_configure_adds_a_stderr_handler_when_logging_is_unconfigured(monkeypatch):
    logger = logging.getLogger(LOGGER_NAME)
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "propagate", True)
    access_log.configure()
    [handler] = logger.handlers
    assert handler.stream is sys.stderr
    assert logger.level == logging.INFO
    assert logger.propagate is False


def test_configure_leaves_existing_logging_in_place(monkeypatch):
    logger = logging.getLogger(LOGGER_NAME)
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "propagate", True)
    root_handlers = list(logging.getLogger().handlers)
    assert root_handlers
    access_log.configure()
    assert logger.handlers == []
    assert logger.propagate is True
    assert logger.level == logging.INFO
    assert logging.getLogger().handlers == root_handlers
