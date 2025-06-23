# VaultWarden-LDAP-Sync

## Overview
VaultWarden-LDAP-Sync keeps a VaultWarden organisation’s user list in sync with an LDAP directory (389-DS / FreeIPA / OpenLDAP, …).
It runs inside a container and performs a reconciliation loop at a configurable interval.
All behaviour is driven by environment variables.

### Health behaviour
* Each loop calls the **sync engine**.
* On success the consecutive-failure counter is reset.
* On an un-handled exception the counter is incremented.
* When `MAX_CONSECUTIVE_FAILURES` is reached the process exits with code 1. Your orchestrator (Docker Compose, Kubernetes, …) should restart the container and alert as desired.

For CI or smoke testing set `RUN_ONCE=1`; the container will run a single sync cycle and then exit (0 on success, 1 on failure).

## Quick Start
1. `cp .env.example .env` and fill in LDAP and VaultWarden credentials.
2. `docker compose -f docker-compose.ldap-sync.yml up --build`.
3. Watch logs; after every `SYNC_INTERVAL` seconds a new sync cycle starts.

**Skip the build:** a pre-built image is available on Docker Hub – `chistokhinsv/vaultwarden-ldap-sync:latest`.  Pull it with:

```bash
docker pull chistokhinsv/vaultwarden-ldap-sync:latest
```

## Environment variables
| Variable | Default | Description |
|----------|---------|-------------|
| **General** |||
| `DEBUG` | `0` | Debug logging mode. |
| `SYNC_INTERVAL` | `60` | Seconds between sync cycles. |
| `RUN_ONCE` | `0` | If truthy (`1`,`true`,`yes`,`on`) run a single cycle and exit. |
| `MAX_CONSECUTIVE_FAILURES` | `5` | Exit with error after this many failed cycles in a row. |
| **VaultWarden** |||
| `VW_URL` | `http://localhost:8080` | VaultWarden base URL. |
| `VW_USER_CLIENT_ID` | — | `user.`-scoped OAuth client id. |
| `VW_USER_CLIENT_SECRET` | — | OAuth client secret for above id. |
| `VW_ORG_ID` | — | Organisation UUID or `organization.<uuid>`. |
| `IGNORE_VW_CERT` | `false` | Ignore invalid HTTPS cert. |
| **LDAP** |||
| `LDAP_HOST` | `ldap://localhost:389` | LDAP/LDAPS host URI. |
| `LDAP_BIND_DN` | — | Bind DN. |
| `LDAP_BIND_PASSWORD` | — | Bind password. |
| `LDAP_BASE_DN` | — | Search base. |
| `LDAP_OBJECT_TYPE` | — | e.g. `inetOrgPerson` (optional). |
| `LDAP_USER_GROUPS` | — | Comma-separated list of group DNs that users must belong to (optional). |
| `LDAP_GROUP_ATTRIBUTE` | `memberOf` | Attribute that lists group membership. |
| `LDAP_FILTER` | — | Additional LDAP filter fragment. |
| `LDAP_MAIL_FIELD` | `mail` | Attribute containing user e-mail. |
| `LDAP_DISABLED_ATTRIBUTE` | `nsAccountLock` | Attribute marking disabled users. |
| `LDAP_DISABLED_VALUES` | `TRUE,true,1,yes,YES` | Comma list of values meaning *disabled*. |
| `LDAP_MISSING_IS_DISABLED` | `false` | Treat missing `LDAP_DISABLED_ATTRIBUTE` as disabled. |
| `LDAP_USERS_ONLY` | `false` | Revoke VaultWarden users not found in LDAP. |
| `IGNORE_LDAPS_CERT` | `false` | Ignore invalid LDAPS cert. |
| `LDAP_CA_FILE` | — | Custom CA bundle file path. |
| **Safety** |||
| `PREVENT_SELF_LOCK` | `true` | Never revoke the account whose client id/secret is used for sync. |

Boolean variables understand any of `1`, `true`, `yes`, `on` (case-insensitive) as **true**.

## Example Compose service
```yaml
services:
  vaultwarden-ldap-sync:
    build: .
    env_file:
      - .env
    depends_on:
      - org_invite_vaultwarden
    # or use image instead of building it
    # image: chistokhinsv/vaultwarden-ldap-sync:latest
    restart: on-failure
```
