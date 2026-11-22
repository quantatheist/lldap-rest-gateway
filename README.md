# LLDAP REST Gateway

Standalone Go REST-to-GraphQL adapter for LLDAP. **No Authentik, Symfony, OIDC, JWT, or external identity provider dependency.** Uses one static high-entropy API key for incoming REST requests, and a separate LLDAP service-account password for upstream GraphQL requests.

## Authentication

Every `/api/v1/` request requires the HTTP header `X-API-Key`. Configure `API_KEY_FILE` (preferred) or `API_KEY`. The API key must be at least 32 characters; generate a random key:

```sh
mkdir -p secrets && chmod 700 secrets
openssl rand -hex 32 > secrets/gateway_api_key
chmod 600 secrets/gateway_api_key
printf '%s' 'YOUR_LLDAP_SERVICE_ACCOUNT_PASSWORD' > secrets/lldap_api_password
chmod 600 secrets/lldap_api_password
```

Do not commit secrets. The API key is hashed in memory with SHA-256 and compared in constant time. The configured key grants **all** API operations; there are no per-client or per-group permissions. Rotate by changing the secret and restarting the container. Never expose the API without HTTPS, VPN, or a trusted internal network.

## Configuration

| Variable | Required | Default |
| --- | --- | --- |
| `LLDAP_URL` | No | `http://lldap:17170` |
| `LLDAP_USERNAME` | No | `admin` |
| `LLDAP_PASSWORD_FILE` or `LLDAP_PASSWORD` | Yes | — |
| `API_KEY_FILE` or `API_KEY` | Yes | — |
| `LISTEN_ADDR` | No | `:8080` |

The gateway logs into LLDAP using `/auth/simple/login`, then forwards predefined GraphQL operations to `/api/graphql`. It does not expose an arbitrary GraphQL proxy.

## Endpoints

| Method | Path |
| --- | --- |
| GET, POST | `/api/v1/users` |
| GET, PATCH, DELETE | `/api/v1/users/{id}` |
| GET, POST | `/api/v1/groups` |
| GET, PATCH, DELETE | `/api/v1/groups/{id}` |
| PUT, DELETE | `/api/v1/groups/{id}/members/{userId}` |
| GET | `/api/v1/schema` |
| GET | `/health/live`, `/health/ready` (public) |

Example:

```sh
curl -H "X-API-Key: $GATEWAY_API_KEY" http://lldap-rest-gateway:8080/api/v1/users
```

## Deployment

Add `deploy/compose.gateway.yaml`'s service and top-level secrets to the **existing LLDAP Compose file**. Since the containers are in the same Compose project, Docker DNS resolves `lldap` without extra networks. No `ports` mapping is needed for same-network clients. Keep the existing `ldap.domain.tld` Nginx Proxy Manager host pointing at LLDAP. Do not publish the gateway on a public host until TLS, network restrictions, and abuse protection are in place.

## Build and publish

```sh
go test ./...
go vet ./...
docker build -t lldap-rest-gateway:dev .
```

GitHub Actions builds multi-architecture images on push to `main` and tags, publishing to GHCR.

## Limitations

This remains an initial implementation, **not production-audited**. Single all-powerful API key, no rate limiting or audit trail, no OpenAPI document, no complete attribute-schema mutations, and no password reset. LLDAP GraphQL errors map to HTTP 502; membership PUT/DELETE are not guaranteed idempotent. Verify against your installed LLDAP version before using write operations. `/health/ready` tests only HTTP reachability, not successful LLDAP login.
