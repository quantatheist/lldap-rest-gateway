# LLDAP REST Gateway (initial implementation)

Standalone Go HTTP gateway for LLDAP GraphQL, with OIDC RS256 JWT validation, client allowlisting and OAuth scopes. This is an **initial implementation**, not yet production-audited. No database and no application-specific registration logic.

## Supported endpoints

| Method | Path | Required scope |
| --- | --- | --- |
| GET | `/api/v1/users` | `users:read` |
| GET | `/api/v1/users/{id}` | `users:read` |
| POST | `/api/v1/users` | `users:write` |
| PATCH | `/api/v1/users/{id}` | `users:write` |
| DELETE | `/api/v1/users/{id}` | `users:write` |
| GET | `/api/v1/groups` | `groups:read` |
| GET | `/api/v1/groups/{id}` | `groups:read` |
| POST | `/api/v1/groups` | `groups:write` |
| PATCH | `/api/v1/groups/{id}` | `groups:write` |
| DELETE | `/api/v1/groups/{id}` | `groups:write` |
| PUT / DELETE | `/api/v1/groups/{id}/members/{userId}` | `groups:write`, `memberships:write` |
| GET | `/api/v1/schema` | `schema:read` |
| GET | `/health/live` | public |
| GET | `/health/ready` | public |

`POST /users` passes the JSON object to `CreateUserInput`; `PATCH /users/{id}` passes it to `UpdateUserInput` with path `id`; `PATCH /groups/{id}` passes it to `UpdateGroupInput` with path `id`. Input field names must match the installed LLDAP GraphQL schema. `POST /groups` expects `{"displayName":"example"}`. LLDAP GraphQL errors currently map to HTTP 502, not detailed REST 4xx errors. Membership PUT/DELETE currently forwards LLDAP mutations directly and **is not guaranteed idempotent**. Do not rely on it for retry-safe workflows without additional reconciliation.

## Configuration

Required: `LLDAP_PASSWORD` or `LLDAP_PASSWORD_FILE`, `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL` (HTTPS), `ALLOWED_CLIENT_IDS` (comma-separated exact client IDs). Optional: `LLDAP_URL` (default `http://lldap:17170`), `LLDAP_USERNAME` (default `admin`), `LISTEN_ADDR` (default `:8080`).

Access tokens must be **RS256-signed JWTs** with matching `iss`, `aud`, `exp`, client ID in `client_id` or `azp`, and space-delimited `scope` or `scp` array. The gateway does not issue tokens. Confirm that your Authentik provider actually emits these claims in access tokens. JWKS is cached for 5 minutes; signing-key rotation can cause temporary failures. LLDAP login tokens are cached for 10 minutes and renewed on 401.

**Security limits:** No per-group authorization, no built-in rate limiting, no audit trail, no token revocation introspection, no OpenAPI document, no full attribute-schema mutation endpoints, and no password reset support yet. Use a dedicated LLDAP account with appropriate privileges; verify LLDAP permissions. Restrict Docker network access and consider NPM access lists or VPN before exposing it publicly. `groups:write` is broad; do not give it to untrusted clients. The `*` scope grants all actions. Do not use production secrets in git.

## Local build and tests

```bash
go test ./...
go build -trimpath -o gateway .
docker build -t lldap-rest-gateway:dev .
```

## Deployment into an existing LDAP stack

1. Create a dedicated shared external network if needed: `docker network create ldap_internal`.
2. Attach your **existing** `lldap` service to that network, keeping its current volume, database, ports and NPM host `ldap.domain.tld` unchanged. The gateway expects DNS name `lldap` on that network; add an alias if your service is named differently.
3. Set the real GHCR owner in `deploy/compose.gateway.yaml`. Configure an Authentik OAuth/OIDC provider with RS256-signed JWT access tokens, appropriate audience, client identifier and scopes. Verify the JWKS URL and issuer against your actual Authentik discovery document; the included URLs are placeholders.
4. Put the LLDAP service-account password in `deploy/secrets/lldap_api_password` (chmod 600, never commit). The example compose file is standalone; from its directory run `docker compose -f compose.gateway.yaml up -d`.
5. Connect the Symfony app or any other client to `http://lldap-rest-gateway:8080` via a shared internal Docker network. Do not point it at `ldap.domain.tld`; that domain can continue to serve the LLDAP UI and GraphQL for legacy clients.
6. Optionally connect gateway to the NPM network and create **a separate** `ldap-api.domain.tld` proxy host forwarding to `lldap-rest-gateway:8080`. Enable HTTPS, restrict access, and apply edge rate limits.
7. Check `GET /health/live` and `GET /health/ready`, then test read-only API calls before any write operations.

For multi-stack deployment, ensure both stacks reference the **same external Docker network** and the gateway service is discoverable from clients. The example compose intentionally attaches only `ldap_internal` and does not expose any host ports.

## GHCR

Push to `main` to trigger `.github/workflows/image.yml`. This builds amd64/arm64 images and publishes `ghcr.io/<owner>/<repo>:main` and a SHA tag. Version tags such as `v0.1.0` publish a semver tag. Set package visibility/permissions in GitHub as needed. GitHub Actions workflows are supplied but have not been executed here.
