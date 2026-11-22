# LLDAP REST Gateway

Independent Go HTTP REST adapter for LLDAP's GraphQL API. **No Authentik, Symfony, OIDC, JWT issuer, or other application dependency.** The gateway authenticates callers using individually scoped API keys and authenticates upstream to LLDAP using a service account.

> **Release status:** Security-hardening candidate, **not independently security-audited or certified production-ready**. Run the CI checks and test read/write operations against your exact LLDAP version in staging. Do not deploy publicly until you have verified NPM TLS, Docker networking, backup/restore and logging.

## Security model

- Each client has a unique API key, stored as a SHA-256 digest in a JSON configuration file mounted as a Docker secret. Generate a uniformly random 32-byte key; never use passwords as API keys.
- Scope checks are performed before upstream access. The supported scopes are `users:read`, `users:create`, `users:update`, `users:delete`, `groups:read`, `groups:create`, `groups:update`, `groups:delete`, `memberships:write`, and `schema:read`. Group membership writes also require `groups:update`.
- Per-client fixed-window in-memory rate limit (`RATE_LIMIT_PER_MINUTE`, default 60). Limits are per instance and reset on restart; use NPM or edge controls for distributed denial-of-service protection.
- The gateway only exposes predefined GraphQL operations; callers cannot submit arbitrary GraphQL documents.
- Structured audit logs contain client name, HTTP method, endpoint category, status and duration, but no API key, request body or user identifier.
- No CORS is enabled. Call the gateway **server-to-server**, never from public browser JavaScript.
- The gateway uses the configured LLDAP account's privileges. The gateway cannot grant more upstream access than that account; carefully restrict account access where LLDAP supports it.

## Quick start: Windows PowerShell 5.1 or newer

Run in the directory containing your Compose file:

```powershell
New-Item -ItemType Directory -Force -Path .\secrets | Out-Null
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$key = [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))).Replace("-", "").ToLowerInvariant() } finally { $sha.Dispose() }
@(@{ name="registration"; key_sha256=$hash; permissions=@("users:read","users:create","users:update","groups:read") }) |
    ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 .\secrets\gateway_clients.json
# NOTE: Windows PowerShell 5.1 Set-Content -Encoding UTF8 adds a BOM. Remove it:
$json = Get-Content .\secrets\gateway_clients.json -Raw
[IO.File]::WriteAllText((Join-Path (Get-Location) "secrets\gateway_clients.json"), $json.TrimStart([char]0xFEFF), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Save this API key in your application's secret store (shown only once): $key"
```

Create `secrets/lldap_api_password` containing **only** the LLDAP service account password (no trailing newline). Never commit either file. In Linux deployments, ensure the container user (UID 65532) can read the files, for example via appropriate ownership/ACLs. With Docker Desktop, verify that both paths are **files**, not directories.

### Linux / Ubuntu

```bash
mkdir -p secrets && chmod 700 secrets
key="$(openssl rand -hex 32)"
hash="$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)"
printf '[{"name":"registration","key_sha256":"%s","permissions":["users:read","users:create","users:update","groups:read"]}]\n' "$hash" > secrets/gateway_clients.json
printf 'Your LLDAP service account password here' > secrets/lldap_api_password
sudo chown 65532:65532 secrets/gateway_clients.json secrets/lldap_api_password
sudo chmod 400 secrets/gateway_clients.json secrets/lldap_api_password
printf 'Save the API key in the application secret store: %s\n' "$key"
unset key
```

The `key_sha256` field is the lowercase 64-character hex SHA-256 of the **actual random API key**, not the key itself. Do not use the digest as the request header. Use different keys per environment. Rotating a key requires updating the client config and restarting the gateway. Treat the hash file as sensitive configuration even though it does not contain plaintext keys.

## Client configuration

`CLIENTS_FILE=/run/secrets/gateway_clients` points to a JSON array:

```json
[
  {
    "name": "read-only-app",
    "key_sha256": "REPLACE_WITH_64_CHARACTER_SHA256_HEX",
    "permissions": ["users:read", "groups:read"]
  },
  {
    "name": "registration",
    "key_sha256": "REPLACE_WITH_DIFFERENT_64_CHARACTER_SHA256_HEX",
    "permissions": ["users:read", "users:create", "users:update", "groups:read"]
  }
]
```

The gateway rejects invalid scopes, duplicate client names and duplicate hashes at startup. Maximum 100 clients. Changes are loaded at startup, not hot-reloaded.

## Environment variables

| Name | Description | Default |
| --- | --- | --- |
| `LLDAP_URL` | Internal LLDAP web endpoint | `http://lldap:17170` |
| `LLDAP_USERNAME` | LLDAP service account | `admin` |
| `LLDAP_PASSWORD_FILE` | Password secret file | required (or `LLDAP_PASSWORD`) |
| `CLIENTS_FILE` | Client hash/scope JSON file | **required** |
| `RATE_LIMIT_PER_MINUTE` | Requests per client per minute (1–100000) | `60` |
| `LISTEN_ADDR` | Internal HTTP listener | `:8080` |

`API_KEY_FILE` and `API_KEY` from the earlier version are **no longer supported**. Migrate to `CLIENTS_FILE` before updating the container.

## Docker Compose deployment

- **Existing LLDAP stack:** copy the service and top-level secrets from [deploy/compose.gateway.yaml](deploy/compose.gateway.yaml) into your Compose file.
- **Minimal LLDAP + gateway stack:** see [deploy/compose.standalone.yaml](deploy/compose.standalone.yaml). Set the `.env` variables before starting, and ensure `lldap_api_password` matches the account configured in LLDAP.
- No published gateway port is needed when NPM and the gateway share a Docker network. NPM should forward `https://api-ldap.example.org` to `http://lldap-rest-gateway:8080`. Enable a trusted certificate, force HTTPS, and enforce sensible request size limits.
- If NPM is in a different Compose project, attach NPM and gateway to a **dedicated shared external network**. Do not expose the LLDAP GraphQL endpoint to the internet. Restrict NPM access to the gateway; avoid exposing unnecessary containers on that shared network.
- For development only, publish `127.0.0.1:18080:8080` and call `http://localhost:18080`.
- Health endpoints `GET /health/live` and `GET /health/ready` do not require API keys. Readiness checks LLDAP HTTP reachability, **not** authentication or GraphQL success. Consider limiting access to these endpoints at NPM.

## REST API reference

All `/api/v1/` endpoints require `X-API-Key: <plaintext-client-key>`. JSON responses; request bodies are JSON objects, up to approximately 1 MiB. Fields for write requests are passed to the corresponding LLDAP GraphQL input type; consult your LLDAP version's schema for supported fields.

| Method | Endpoint | Scope |
| --- | --- | --- |
| GET | `/api/v1/users` | `users:read` |
| GET | `/api/v1/users/{id}` | `users:read` |
| POST | `/api/v1/users` | `users:create` |
| PATCH | `/api/v1/users/{id}` | `users:update` |
| DELETE | `/api/v1/users/{id}` | `users:delete` |
| GET | `/api/v1/groups` | `groups:read` |
| GET | `/api/v1/groups/{id}` | `groups:read` |
| POST | `/api/v1/groups` | `groups:create` |
| PATCH | `/api/v1/groups/{id}` | `groups:update` |
| DELETE | `/api/v1/groups/{id}` | `groups:delete` |
| PUT, DELETE | `/api/v1/groups/{id}/members/{userId}` | `groups:update` and `memberships:write` |
| GET | `/api/v1/schema` | `schema:read` |

Examples (set `GATEWAY_URL` and `GATEWAY_API_KEY` as secret environment variables in your application):

```bash
curl -fsS -H "X-API-Key: $GATEWAY_API_KEY" "$GATEWAY_URL/api/v1/users"
curl -fsS -H "X-API-Key: $GATEWAY_API_KEY" "$GATEWAY_URL/api/v1/groups"
curl -fsS -X POST -H "X-API-Key: $GATEWAY_API_KEY" -H "Content-Type: application/json" \
  -d '{"id":"test-user","email":"test@example.org","displayName":"Test User"}' \
  "$GATEWAY_URL/api/v1/users"
```

Only use the write example in a disposable test environment. GraphQL schema differences may reject fields.

### Using the gateway in another application

Keep the API key on the **backend**, never embed it in HTML or client-side JS. Example with Node.js 20+:

```js
const response = await fetch(`${process.env.GATEWAY_URL}/api/v1/users`, {
  headers: { "X-API-Key": process.env.GATEWAY_API_KEY },
  signal: AbortSignal.timeout(8000)
});
if (!response.ok) throw new Error(`LLDAP gateway HTTP ${response.status}`);
const users = await response.json();
```

Python example:

```python
import os
import requests

r = requests.get(
    os.environ["GATEWAY_URL"].rstrip("/") + "/api/v1/users",
    headers={"X-API-Key": os.environ["GATEWAY_API_KEY"]},
    timeout=8,
)
r.raise_for_status()
users = r.json()
```

Status codes: `401` missing/invalid key, `403` insufficient scope, `405` unsupported method on known resources, `429` rate limit exceeded, `502` upstream failure, `503` readiness failure. Do not retry non-idempotent writes automatically; a timeout does not prove that LLDAP did not apply a mutation.

## Tests and operations

```bash
go test -race ./...
go vet ./...
go build ./...
docker compose config --quiet
docker compose up -d lldap-rest-gateway
docker compose logs --tail=100 lldap-rest-gateway
```

Use a staging LLDAP with dummy users to test create/update/delete, membership mutations, error mapping and permissions. Monitor 401/403/429/502 responses and audit logs. Back up LLDAP before rollout. Pin tested LLDAP and gateway image versions/digests; avoid deploying `:latest` or `:main` automatically to production.

### Known limitations

- No independent security audit or live integration test against every LLDAP version.
- In-memory rate limiting is per container, not shared across replicas, and does not protect against a high volume of unauthenticated requests at the proxy.
- API key revocation requires a configuration update and restart; no key expiry or self-service rotation endpoint.
- Audit events log endpoint category, not exact object IDs, by design.
- GraphQL response size is capped, but the gateway does not yet provide pagination.
- LLDAP GraphQL input compatibility varies with version; user and group update bodies are not yet validated against a complete local JSON schema.
- Health readiness does not authenticate to LLDAP. Group membership mutations may not be idempotent.
- No OpenAPI document or built-in distributed metrics.
