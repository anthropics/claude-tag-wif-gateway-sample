# Copyright 2026 Anthropic PBC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Application factory and routes for the Claude Tag sample gateway.

The gateway exposes three things. A readiness route at the root that only
confirms the caller's token maps to a principal, a discovery route that
tells the agent what services it can reach, which is one useful pattern
for making a gateway discoverable, and a proxy route that forwards
requests to a mapped downstream service with a credential injected from
the environment.
"""

import http.cookiejar
import os
from contextlib import asynccontextmanager
from urllib.parse import quote, unquote

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response

from gateway.auth import verify_request
from gateway.constants import OIDC_DISCOVERY_URL
from gateway.jwks import JWKSCache
from gateway.mapping import AccessConfig, Principal

# Only these request headers are forwarded to the downstream service.
# The gateway calls the downstream on its own credentialed connection,
# so an allowlist keeps caller-supplied trust context (X-Forwarded-For,
# X-Real-IP, X-Forwarded-Host, X-Forwarded-Proto, Forwarded, and
# similar) from reaching the downstream, where it would arrive with the
# gateway's authority and let an authorized agent spoof request
# provenance. It also keeps the inbound Authorization header (the Claude
# Tag token, a live credential) and cookies from leaking to a party they
# were not minted for. Extend this list deliberately when your
# downstream needs more headers, and never forward trust-context
# headers your downstream service believes.
_FORWARDED_REQUEST_HEADERS = {
    "accept",
    "accept-language",
    "content-type",
}

_FORWARDED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


class _DropCookieJar(http.cookiejar.CookieJar):
    """A cookie jar that stores nothing."""

    def set_cookie(self, cookie):
        return


def sanitize_downstream_path(downstream_path: str) -> str | None:
    """Returns a safely re encoded path or None when the path is hostile.

    Each segment (already percent decoded once by the server) is decoded
    one more time, rejected if it could read as a dot segment or
    separator anywhere in the decode/normalize chain, and re encoded.
    Deliberately conservative for a sample: literal "%", "/", "\\", ";",
    ":", "?", "#", and non printable or non ASCII characters are
    rejected outright. If an upstream legitimately uses one of these
    characters in paths (":" in `resource:action` style APIs, say),
    drop it from the rejection list below and accept that upstreams
    which rewrite that character can see a traversal segment.
    """
    safe_segments = []
    segments = downstream_path.split("/")
    for index, segment in enumerate(segments):
        decoded = unquote(segment)
        if decoded == "":
            # A lone or trailing empty segment is the service root; an
            # interior one would forward "//", which upstreams normalize
            # unpredictably.
            if index < len(segments) - 1:
                return None
            safe_segments.append("")
            continue
        # Some upstreams rewrite a decoded path again (";"
        # path-parameter stripping, Win32 trailing dot and space
        # stripping, NUL truncation, NTFS alternate data stream
        # stripping at ":"), so a segment this gateway forwards as
        # harmless can collapse into a dot segment on the other side.
        # The checks below reject the inputs of these rewrites; an
        # upstream with a rewrite not listed here needs its own entry.
        if (
            not decoded.isascii()
            or not decoded.isprintable()
            or "%" in decoded
            or "/" in decoded
            or "\\" in decoded
            or ";" in decoded
            or ":" in decoded
            or "?" in decoded
            or "#" in decoded
            or decoded != decoded.rstrip(". ")
        ):
            return None
        safe_segments.append(quote(decoded, safe=""))
    return "/".join(safe_segments)


async def _authorize(request: Request) -> Principal:
    claims = await verify_request(request)
    principal = request.app.state.config.resolve_principal(claims)
    if principal is None:
        # The token is genuine but this agent has no mapping, so the
        # request is forbidden rather than unauthorized.
        raise HTTPException(
            status_code=403, detail="agent is not mapped to a principal"
        )
    return principal


def create_app(
    config_path: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    jwks_cache: JWKSCache | None = None,
) -> FastAPI:
    config = AccessConfig.load(
        config_path or os.environ.get("GATEWAY_CONFIG", "config.yaml")
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.config = config
        client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(10.0), follow_redirects=False
        )
        # One client is shared by every principal's proxied requests, so
        # its cookie jar must never store an upstream Set-Cookie: a
        # stored cookie would be replayed on later requests made for
        # other principals, bleeding session state across the boundary
        # this gateway exists to enforce. Assigned in the lifespan so an
        # injected client is covered too.
        client.cookies = _DropCookieJar()
        app.state.http_client = client
        app.state.jwks = jwks_cache or JWKSCache(
            app.state.http_client, OIDC_DISCOVERY_URL
        )
        try:
            yield
        finally:
            if http_client is None:
                await app.state.http_client.aclose()

    app = FastAPI(
        title="Claude Tag sample gateway",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.api_route("/", methods=["GET", "POST"], dependencies=[Depends(_authorize)])
    async def readiness():
        """Confirms the caller's token maps to a principal; reads no body."""
        return {"ok": True}

    @app.get("/list-services")
    async def list_services(
        request: Request, principal: Principal = Depends(_authorize)
    ):
        """Tells the calling agent what it can reach through this gateway."""
        services = [
            {
                "name": service.name,
                "description": service.description,
                "path": f"/services/{service.name}/",
            }
            for service in request.app.state.config.services.values()
            if service.name in principal.allowed_services
        ]
        return {"services": services}

    @app.api_route(
        "/services/{service_name}/{downstream_path:path}", methods=_FORWARDED_METHODS
    )
    async def proxy(
        service_name: str,
        downstream_path: str,
        request: Request,
        principal: Principal = Depends(_authorize),
    ):
        if service_name not in principal.allowed_services:
            raise HTTPException(
                status_code=403, detail="service is not allowed for this agent"
            )
        service = request.app.state.config.services.get(service_name)
        if service is None:
            raise HTTPException(status_code=404, detail="unknown service")
        safe_path = sanitize_downstream_path(downstream_path)
        if safe_path is None:
            raise HTTPException(status_code=400, detail="invalid path")
        credential = os.environ.get(service.credential_env)
        if not credential:
            # A missing downstream credential is a deployment problem and
            # the gateway fails closed instead of forwarding without auth.
            raise HTTPException(
                status_code=503, detail="downstream credential not configured"
            )

        forwarded_headers = {
            name: value
            for name, value in request.headers.items()
            if name.lower() in _FORWARDED_REQUEST_HEADERS
        }
        forwarded_headers["Authorization"] = f"Bearer {credential}"

        upstream_response = await request.app.state.http_client.request(
            request.method,
            f"{service.upstream_base_url}/{safe_path}",
            params=request.query_params,
            content=await request.body(),
            headers=forwarded_headers,
        )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
        )

    return app
