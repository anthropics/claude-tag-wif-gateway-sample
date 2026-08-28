# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Claims to principal mapping for the Claude Tag sample gateway.

The mapping lives in a YAML config file. Exact match on the full token
subject is preferred, as the onboarding guide recommends. A channel_id
based mapping is included as an example of authorizing on a claim other
than the subject, which a custom endpoint can do because it verifies the
full token itself.
"""

from dataclasses import dataclass, field

import yaml


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
            channel_principals=channel_principals,
            services=services,
        )

    def resolve_principal(self, claims: dict) -> Principal | None:
        """Returns the principal for verified claims or None when unmapped."""
        subject_match = self.subject_principals.get(claims.get("sub"))
        if subject_match is not None:
            return subject_match
        channel_id = claims.get("channel_id")
        if isinstance(channel_id, str):
            return self.channel_principals.get(channel_id)
        return None
