# Claude Tag Custom Gateway — Sample Implementation

**Sample code. Not maintained and not accepting contributions.** This
is a reference implementation of the "custom gateway" described in the
Claude Tag Identity Federation onboarding guide (Chapter 2, "Custom
endpoint — direct token presentation"). The Claude Tag identity
federation feature is currently in private beta; your Anthropic contact
can tell you whether it is available to your organization. This code is
meant to be read, adapted, and reviewed against your own security
requirements before any production use. It is not a supported product.

## What it does

Anthropic calls your registered endpoint directly, attaching a Claude Tag
identity token to each request in the `Authorization` header as a bearer
token. This gateway:

1. **Validates** every incoming token — signature (ES256, against the
   issuer's published JWKS), exact issuer, your registered audience, and
   expiry. Anything that fails is rejected with a generic 401.
2. **Maps** the verified claims to a principal in your system, from a
   config file — exact-match on the token subject (preferred), with a
   `channel_id`-based mapping shown as an alternative.
3. **Serves a discovery route** (`GET /list-services`) so the agent can
   learn at runtime what this gateway offers — one useful pattern for
   making a gateway discoverable to the model.
4. **Answers a readiness probe** at the root (`GET /` or `POST /`) that
   only confirms the caller's token is valid and maps to a principal.
5. **Proxies** requests to mapped downstream services
   (`/services/{name}/...`), injecting a downstream credential from an
   environment variable. The Claude Tag token itself is never forwarded
   downstream.

## Layout

```
gateway/constants.py   Issuer URL, discovery URL, algorithm allowlist, subject prefix
gateway/jwks.py        OIDC discovery -> jwks_uri -> key cache, refresh on unknown kid
gateway/auth.py        Bearer extraction and the four verify checks from the guide
gateway/mapping.py     Config-file claims -> principal -> allowed services
gateway/main.py        App factory, / readiness, /list-services, /services/{name}/{path} proxy
config.example.yaml    Example mapping config with deliberately fake IDs, plus the
                       reserved registration-test control subject
tests/                 Offline test harness with locally generated throwaway keys
```

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest          # all tests run offline, no Anthropic dependency
cp config.example.yaml config.yaml  # then edit with your real values
.venv/bin/python -m uvicorn gateway.main:create_app --factory --port 8000
```

Or with Docker:

```bash
docker build -t claude-tag-gateway-sample .
docker run -p 8000:8000 \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -e EXAMPLE_API_TOKEN=... \
  claude-tag-gateway-sample
```

## How this maps to the onboarding guide

Follow the guide's Chapter 2 steps with this code side by side.

### Step 1 — Choose an audience value and register your endpoint

Pick your audience string (printable ASCII, no spaces, at most 256 bytes;
values used for cloud token exchange such as `sts.amazonaws.com` are
reserved). Put it in `config.yaml` under `audience`, and send it with
your endpoint URL to your Anthropic contact for registration. If your
organization has access to self-serve registration, you register there
instead and can run the registration test described under "The
readiness route and the registration test" below. If you plan to run
that test, use your gateway's https root URL, with no path or query
string, as the audience: with any other audience the registration call
fails unless you explicitly skip the test.

### Step 2 — Validate tokens at your endpoint

`gateway/auth.py` and `gateway/jwks.py` implement the guide's four
checks:

- **Signature** — keys are fetched from the `jwks_uri` named in the
  discovery document at
  `https://identity.anthropic.com/agents/.well-known/openid-configuration`.
  Only ES256 is accepted. On an unknown key id the key cache refreshes
  once before rejecting, which absorbs key rotation (this is the guide's
  troubleshooting advice, implemented).
- **Issuer** — exactly `https://identity.anthropic.com/agents`.
- **Audience** — the value you registered. On the wire the audience claim
  is a JSON array with one element, which is standard JWT; the code uses
  the library's audience check rather than comparing raw claim text, as
  the guide recommends.
- **Expiry** — tokens live 10 minutes; no leeway is granted.

The test suite (`tests/`) is the guide's step 2.3 made runnable: it
mints tokens with locally generated throwaway keys and verifies the
gateway rejects wrong-audience, bad-signature, and expired tokens (plus
wrong issuer, `alg=none`, unknown key id, and missing claims) and
accepts a valid token against a local JWKS. Everything runs offline.

### Step 3 — Map subjects to principals

The token subject identifies one agent:
`wimse://identity.anthropic.com/org/<YOUR_ORG_ID>/agent/<AGENT_ID>`.
Your Anthropic contact provides your organization ID (starts with
`org_`) and each agent's ID (starts with `cagt_`). Put exact-match
entries in `config.yaml` under `principals`. A `channel_id`-keyed
mapping is shown under `channel_principals` — a custom endpoint can
authorize on any claim because it verifies the full token itself, but a
channel mapping is broader than a subject pin, so prefer subject pins.

**Channel lifecycle caveat (from the guide):** an agent's identity is
tied to its channel. Deleting and recreating a channel — even with the
same name — creates a new agent with a new subject, and pinned mappings
stop matching with no other warning. If that happens, get the new subject
from your Anthropic contact and update `config.yaml`.

### Step 4 — Submit for review and verify end to end (required)

Anthropic reviews every connection configuration in this beta before
enabling it. Send your Anthropic contact: your audience value, where
validation happens, and how subjects map to permissions. The connection
is not enabled until that review is done. After enablement, trigger a
test action from the agent's channel and check your gateway's logs —
token accepted, subject mapped to the expected principal — and that a
request with a different audience is rejected.

## The discovery route

Your gateway is most useful when the model can learn what it wraps and
how to use it. One useful pattern, served by this sample, is
`GET /list-services`, returning the services the calling agent's
principal may use. Mention the route in the identity profile's system
prompt addendum (for example, "call GET /list-services to see what's
available") so the agent reads it at runtime. An OpenAPI spec is an
equally valid shape — see the guide for the current discussion of
discoverability.

## The readiness route and the registration test

`GET /` and `POST /` run the same token validation and principal mapping
as every other route and return `{"ok": true}` for a mapped agent, 403
for a valid token with no mapping, and 401 for any other token failure
(503 if the issuer's key set cannot be fetched). The request body is
ignored and nothing is forwarded. It reveals nothing a caller cannot
already learn from `GET /list-services`. It is not an unauthenticated
health check: a probe without a token gets 401.

The Claude Tag self-serve registration test posts to the audience URL
with an empty body twice: once with a token for a control agent in your
organization, which must get 2xx, and once with a token whose subject
names another organization, which must get 401 or 403. This route is
what answers it, but two configuration points are also required:

- Register the gateway's https root URL, with no path or query string,
  as the audience; the test sends its requests to the audience value
  itself. With an audience that is not an https root URL, registration
  fails unless you explicitly set the test to skip, and then no test
  runs.
- Add a `principals` entry for the control subject, with
  `allowed_services: []`, so the control token maps to a principal
  without reaching any service. If the registration response includes a
  control subject, use that value. If it does not include one yet, the
  control token is minted for a reserved test agent, so the subject is
  `wimse://identity.anthropic.com/org/<YOUR_ORG_ID>/agent/cagt_01YcVfxkQb6JRzqk5kF2tNLh`
  (the same organization ID as your other subjects). Without this entry
  the control gets 403 and the test reports that the gateway rejects
  everything.

Passing this test does not enable the connection by itself; Anthropic
still enables it after the review in Step 4.

## Security properties of this sample

- Fails closed everywhere: no token, bad token, unmapped agent, unknown
  service, or a missing downstream credential all reject the request.
- ES256 only; `alg=none` and algorithm-confusion attempts are rejected
  before key lookup.
- Error responses are generic and never echo token contents.
- FastAPI's interactive documentation and OpenAPI routes (`/docs`,
  `/redoc`, `/openapi.json`) are turned off, so the gateway does not
  publish its route list.
- Request headers are forwarded on an allowlist (`Accept`,
  `Accept-Language`, `Content-Type`) and the `Authorization` header is
  replaced with the downstream credential, so the Claude Tag token is
  never forwarded to downstream services — and neither is
  caller-supplied trust context (`X-Forwarded-For`, `X-Real-IP`,
  `Forwarded`, and similar), which would otherwise arrive on the
  gateway's credentialed connection and let an authorized agent spoof
  its network identity to your services.
- Proxied path segments are decoded, checked for traversal (including
  multiply encoded forms), and re-encoded to one unambiguous encoding
  before the upstream URL is built. The check is deliberately
  conservative: it also rejects every character some class of upstream
  server is known to rewrite back into a traversal sequence, including
  ":" (stripped with the rest of an NTFS alternate data stream suffix
  on Windows/IIS-style servers). If a service you proxy legitimately
  uses ":" in paths (some APIs do, for example `resource:action`
  method names), remove `":"` from the rejection list in
  `sanitize_downstream_path` in `gateway/main.py` for your
  deployment; in exchange you accept the traversal risk on any upstream
  that strips a colon suffix, so only loosen this when no such server
  can sit behind the gateway.
- No secrets in config: downstream credentials come from environment
  variables named in the config, never values in it.
- Dependencies are pinned exactly in `requirements.txt`.
- All claim comparisons happen on signature-verified data via the JWT
  library, so no manual secret comparison exists in this code. If you add
  your own shared-secret check (for example an extra header), compare it
  with `hmac.compare_digest`, not `==`.

## Accepted known limitations

Known gaps, deliberately accepted in this sample; review them against
your own requirements before any production use:

- The optional channel-based agent mapping does not also check the
  agent's organization; the audience check is the only
  cross-organization barrier on that path. Prefer exact subject pins.
- The key-set URL named by the issuer's discovery document is fetched
  wherever it points (any HTTPS host); it is not pinned to the
  issuer's own host.
- An issuer that empties its published key set is not honored until
  the gateway restarts; previously fetched keys keep verifying tokens
  until then.

## Before production

At minimum: terminate TLS in front of the gateway, add rate limiting and
structured logging (log the subject and decision, never the token), cap
how long previously fetched signing keys may keep being served when JWKS
refreshes fail repeatedly (this sample serves its last good key set
until a refresh succeeds), pin your container base image by digest, consider hash-pinned dependency
installs (`requirements.lock.txt` pins the full dependency tree with
hashes: `pip install --require-hashes -r requirements.lock.txt`), and
run your own security review. The subject prefix (`wimse://`) is the Workload
Identifier URI form defined by the IETF WIMSE working group
(draft-ietf-wimse-identifier) — it is a single named constant in
`gateway/constants.py`. The gateway checks that scheme, and a subject pin
matches the full identifier exactly, never by prefix, as that draft specifies.
The optional channel mapping in Step 3 does not match the identifier at all.
