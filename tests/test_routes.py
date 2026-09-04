# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

# Claude Tag identity federation public beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

"""Readiness, discovery, and proxy route tests."""

from tests.conftest import TEST_CREDENTIAL, TEST_UPSTREAM, UNMAPPED_SUBJECT


def test_proxy_forwards_and_injects_credential(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/v1/things?q=1", token=token)
    assert response.status_code == 200
    assert response.json() == {"upstream": "ok"}
    assert len(harness.upstream_requests) == 1
    upstream = harness.upstream_requests[0]
    assert str(upstream.url) == f"{TEST_UPSTREAM}/v1/things?q=1"
    assert upstream.headers["authorization"] == f"Bearer {TEST_CREDENTIAL}"


def test_proxy_never_forwards_the_agent_token(harness):
    token = harness.mint()
    harness.get("/services/example-api/v1/things", token=token)
    upstream = harness.upstream_requests[0]
    for value in upstream.headers.values():
        assert token not in value


def test_proxy_requires_auth(harness):
    assert harness.get("/services/example-api/v1/things").status_code == 401


def test_proxy_blocks_service_not_allowed_for_principal(harness):
    token = harness.mint()
    assert harness.get("/services/other-api/v1/things", token=token).status_code == 403
    assert harness.upstream_requests == []


def test_proxy_rejects_path_traversal(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/%2e%2e/admin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_double_encoded_traversal(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/%252e%252e/admin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_triple_encoded_traversal(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/%25252e%25252e/admin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_backslash_segment(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/..%5cadmin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_encoded_slash_traversal(harness):
    # Encoded deeply enough that one decode level still remains when the
    # sanitizer sees the segment; without the slash check this reaches
    # the upstream as ..%2Fadmin.
    token = harness.mint()
    response = harness.get("/services/example-api/..%25252fadmin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_fully_encoded_slash_traversal(harness):
    token = harness.mint()
    response = harness.get(
        "/services/example-api/%25252e%25252e%25252fadmin", token=token
    )
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_encoded_backslash_segment(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/..%255cadmin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_semicolon_path_parameter_segment(harness):
    # Forwarded verbatim, "..;" collapses to ".." on upstreams that strip
    # ";" path parameters while routing.
    token = harness.mint()
    response = harness.get("/services/example-api/..%3Bjsessionid=x/admin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_trailing_dot_segment(harness):
    # Forwarded verbatim, ".. " and "..." collapse to ".." on upstreams
    # that strip trailing dots and spaces from path components.
    token = harness.mint()
    for hostile in ("..%20", "...", "..%2e"):
        response = harness.get(
            f"/services/example-api/{hostile}/admin", token=token
        )
        assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_control_character_segment(harness):
    # Forwarded verbatim, "..%00" collapses to ".." on upstreams that
    # truncate path components at a NUL byte.
    token = harness.mint()
    response = harness.get("/services/example-api/..%2500/admin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_non_ascii_segment(harness):
    # Non-ASCII lookalikes (here a fullwidth full stop) can normalize
    # into ASCII dots on the upstream's filesystem or framework.
    token = harness.mint()
    response = harness.get("/services/example-api/%2E%2E%EF%BC%8E/admin", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_forwards_one_unambiguous_encoding(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/file%2520name", token=token)
    assert response.status_code == 200
    upstream = harness.upstream_requests[0]
    assert upstream.url.raw_path.endswith(b"/file%20name")


def test_proxy_fails_closed_without_downstream_credential(harness, monkeypatch):
    monkeypatch.delenv("EXAMPLE_API_TOKEN")
    token = harness.mint()
    assert (
        harness.get("/services/example-api/v1/things", token=token).status_code == 503
    )
    assert harness.upstream_requests == []


def test_proxy_rejects_interior_empty_segment(harness):
    # Interior empty segments forward "//" sequences, which upstreams
    # normalize unpredictably; the service root and trailing slashes
    # stay valid.
    token = harness.mint()
    assert harness.get("/services/example-api//admin", token=token).status_code == 400
    assert harness.get("/services/example-api/a//b", token=token).status_code == 400
    assert harness.upstream_requests == []
    assert harness.get("/services/example-api/", token=token).status_code == 200
    assert harness.get("/services/example-api/a/", token=token).status_code == 200


def test_proxy_rejects_query_and_fragment_delimiters(harness):
    # Forwarded as "..%3F"/"..%23", these collapse to ".." on upstreams
    # that decode and then re-parse the path at a query or fragment
    # delimiter, the same class the ";" rejection defends against.
    token = harness.mint()
    for hostile in ("..%3Fx", "..%23x"):
        response = harness.get(
            f"/services/example-api/{hostile}/admin", token=token
        )
        assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_colon_segment(harness):
    # Forwarded verbatim, "..::$DATA" collapses to ".." on upstreams
    # that strip an NTFS alternate data stream suffix at the first ":".
    token = harness.mint()
    for hostile in ("..::$DATA", "..%3A%3A%24DATA", "..%3A", "..%253A"):
        response = harness.get(
            f"/services/example-api/{hostile}/admin", token=token
        )
        assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_rejects_interior_colon_segment(harness):
    token = harness.mint()
    response = harness.get("/services/example-api/a%3Ab/c", token=token)
    assert response.status_code == 400
    assert harness.upstream_requests == []


def test_proxy_does_not_replay_upstream_cookies(harness):
    # The upstream sets a session cookie on the first response. A later
    # proxied request must not carry it: the shared client would
    # otherwise replay one principal's upstream session on requests made
    # for other principals.
    token = harness.mint()
    assert harness.get("/services/example-api/set-cookie", token=token).status_code == 200
    assert harness.get("/services/example-api/v1/things", token=token).status_code == 200
    second_upstream_request = harness.upstream_requests[1]
    assert "cookie" not in second_upstream_request.headers


def test_discovery_route_lists_only_allowed_services(harness):
    token = harness.mint()
    response = harness.get("/list-services", token=token)
    names = [service["name"] for service in response.json()["services"]]
    assert "other-api" not in names


def test_proxy_does_not_forward_caller_trust_context_headers(harness):
    token = harness.mint()
    harness.get(
        "/services/example-api/v1/things",
        token=token,
        headers={
            "X-Forwarded-For": "203.0.113.9",
            "X-Real-IP": "203.0.113.9",
            "X-Forwarded-Host": "internal.example.test",
            "X-Forwarded-Proto": "https",
            "Forwarded": "for=203.0.113.9",
        },
    )
    upstream = harness.upstream_requests[0]
    for name in (
        "x-forwarded-for",
        "x-real-ip",
        "x-forwarded-host",
        "x-forwarded-proto",
        "forwarded",
    ):
        assert name not in upstream.headers


def test_proxy_forwards_only_allowlisted_headers(harness):
    token = harness.mint()
    harness.get(
        "/services/example-api/v1/things",
        token=token,
        headers={"Accept": "application/json", "X-Custom-Header": "surprise"},
    )
    upstream = harness.upstream_requests[0]
    assert upstream.headers["accept"] == "application/json"
    assert "x-custom-header" not in upstream.headers


def test_root_confirms_mapped_principal(harness):
    response = harness.get("/", token=harness.mint())
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_root_accepts_empty_post(harness):
    response = harness.client.post(
        "/", headers={"Authorization": f"Bearer {harness.mint()}"}, content=b""
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert harness.upstream_requests == []


def test_root_accepts_post_and_ignores_body(harness):
    response = harness.client.post(
        "/",
        headers={
            "Authorization": f"Bearer {harness.mint()}",
            "Content-Type": "application/json",
        },
        content=b"{not json",
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert harness.upstream_requests == []


def test_root_forbids_unmapped_subject(harness):
    token = harness.mint(sub=UNMAPPED_SUBJECT)
    assert harness.get("/", token=token).status_code == 403
    response = harness.client.post("/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_root_requires_token(harness):
    assert harness.get("/").status_code == 401
    assert harness.client.post("/").status_code == 401


def test_docs_and_openapi_routes_are_disabled(harness):
    token = harness.mint()
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert harness.client.get(path).status_code == 404
        assert harness.get(path, token=token).status_code == 404


def test_root_rejects_wrong_audience(harness):
    token = harness.mint(aud=["some-other-audience"])
    assert harness.get("/", token=token).status_code == 401
    response = harness.client.post("/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
