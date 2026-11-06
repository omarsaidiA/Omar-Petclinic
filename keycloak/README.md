# Keycloak realm `omar-petclinic`

> **DEV ONLY.** `omar-petclinic-realm.json` contains test users with known passwords.
> It is imported automatically by `docker compose up` (`--import-realm`) and must never be used in production.

| User    | Password              | Realm role | Notes                                   |
|---------|-----------------------|------------|-----------------------------------------|
| `admin` | `Admin-DevOnly-2026!` | `ADMIN`    | Full access                             |
| `vet`   | `Vet-DevOnly-2026!`   | `VET`      | Owners/pets read, visits management     |
| `owner` | `Owner-DevOnly-2026!` | `OWNER`    | Linked to owner #1 via the `owner_id` claim |

Client `omar-petclinic-api` is public. Direct access grants (password grant) are enabled only so
tokens can be fetched with `curl` locally; a real deployment would use the authorization code flow with PKCE.

Get a token:

```bash
curl -s -X POST http://localhost:8080/realms/omar-petclinic/protocol/openid-connect/token \
  -d grant_type=password -d client_id=omar-petclinic-api \
  -d username=vet -d 'password=Vet-DevOnly-2026!'
```
