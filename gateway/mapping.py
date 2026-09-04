# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Claims to principal mapping for the Claude Tag sample gateway.

The mapping lives in a YAML config file. Exact match on the full token
subject is preferred, as the onboarding guide recommends. An optional
organization prefix mapping accepts every agent in one organization. A
mapping keyed on the slack_channel_id claim is included as an example
of authorizing on a claim other than the subject, which a custom
endpoint can do because it verifies the full token itself.
"""

from dataclasses import dataclass, field

import yaml

from gateway.constants import (
    AGENT_PATH_SEGMENT,
    ORGANIZATION_SUBJECT_PREFIX,
    REGISTRATION_TEST_AGENT_ID,
)


@dataclass(frozen=True)
class Principal:
    name: str
    allowed_services: frozenset[str]


@dataclass(frozen=True)
class Service:
    name: str
    description: str
    upstream_base_url: str
    credential_env: str


@dataclass(frozen=True)
class AccessConfig:
    audience: str
    subject_principals: dict[str, Principal] = field(default_factory=dict)
    organization_principals: dict[str, Principal] = field(default_factory=dict)
    channel_principals: dict[str, Principal] = field(default_factory=dict)
    services: dict[str, Service] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str) -> "AccessConfig":
        with open(path) as config_file:
            raw = yaml.safe_load(config_file)
        if not isinstance(raw, dict):
            raise ValueError("config file must contain a mapping")
        audience = raw.get("audience")
        if not isinstance(audience, str) or not audience:
            raise ValueError("config file must set a non empty audience")

        def parse_principal(entry: dict) -> Principal:
            return Principal(
                name=str(entry["principal"]),
                allowed_services=frozenset(
                    str(s) for s in entry.get("allowed_services", [])
                ),
            )

        subject_principals = {
            str(entry["subject"]): parse_principal(entry)
            for entry in raw.get("principals", [])
        }
        organization_principals = {
            _validated_subject_prefix(str(entry["subject_prefix"])): parse_principal(
                entry
            )
            for entry in raw.get("organization_principals", [])
        }
        channel_principals = {
            str(entry["channel_id"]): parse_principal(entry)
            for entry in raw.get("channel_principals", [])
        }
        services = {}
        for service_name, entry in (raw.get("services") or {}).items():
            upstream = str(entry["upstream_base_url"]).rstrip("/")
            if not upstream.startswith("https://"):
                raise ValueError("upstream_base_url must use https")
            services[str(service_name)] = Service(
                name=str(service_name),
                description=str(entry.get("description", "")),
                upstream_base_url=upstream,
                credential_env=str(entry["credential_env"]),
            )
        return cls(
            audience=audience,
            subject_principals=subject_principals,
            organization_principals=organization_principals,
            channel_principals=channel_principals,
            services=services,
        )

    def resolve_principal(self, claims: dict) -> Principal | None:
        """Returns the principal for verified claims or None when unmapped."""
        subject = claims.get("sub")
        subject_match = self.subject_principals.get(subject)
        if subject_match is not None:
            return subject_match
        if isinstance(subject, str):
            for prefix, principal in self.organization_principals.items():
                if _is_agent_under_prefix(subject, prefix):
                    return principal
        channel_id = claims.get("slack_channel_id")
        if isinstance(channel_id, str):
            return self.channel_principals.get(channel_id)
        return None


def _validated_subject_prefix(prefix: str) -> str:
    # Requiring the trailing "/agent/" anchors the match at the path
    # delimiter, so an organization id cannot match a longer id that
    # starts with the same characters.
    if not prefix.startswith(ORGANIZATION_SUBJECT_PREFIX) or not prefix.endswith(
        AGENT_PATH_SEGMENT
    ):
        raise ValueError(
            "subject_prefix must be the organization's full subject prefix, "
            f"{ORGANIZATION_SUBJECT_PREFIX}<organization id>{AGENT_PATH_SEGMENT}"
        )
    organization_id = prefix[len(ORGANIZATION_SUBJECT_PREFIX) :]
    organization_id = organization_id[: -len(AGENT_PATH_SEGMENT)]
    if not organization_id or "/" in organization_id:
        raise ValueError("subject_prefix must name exactly one organization id")
    return prefix


def _is_agent_under_prefix(subject: str, prefix: str) -> bool:
    agent_id = subject.removeprefix(prefix)
    if agent_id == subject or agent_id == "" or "/" in agent_id:
        return False
    return agent_id != REGISTRATION_TEST_AGENT_ID
