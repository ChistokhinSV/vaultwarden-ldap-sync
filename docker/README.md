# VaultWarden Dev Container Setup

This guide describes how to build and run a reproducible VaultWarden development container for local testing and CI/CD.

---

## Features
- **Admin panel** enabled with a fixed token
- **Signups allowed** for initial user creation
- Data persisted in a Docker volume
- Easy to populate with a test user and organisation

---

## Quick Start

1. **Start VaultWarden**

```sh
cd docker
# Start the dev VaultWarden instance
docker compose -f docker-compose.vaultwarden.yml up -d
```

- Web UI: [http://localhost:8080](http://localhost:8080)
- Admin Panel: [http://localhost:8080/admin](http://localhost:8080/admin)
  - Admin Password: `vaultwarden`
  - Admin Token: 
    ```
    $argon2id$v=19$m=65540,t=3,p=4$feGEx6pnYAk48r0C9gAhcRLEksQxZ09dZxlxpKz735I$9O66H64jds3g2fRxJTmazL7Kj0BPvaQ+0UVHsChJqJI
    ```

2. **Create Test User and Organisation**

- Register a new user:
  - Email: `user@domain.local`
  - Password: `vaultwarden1234`
- Log in as this user
- Create an organisation named `vaultwarden`

3. **Retrieve IDs and Secrets**

- Use the admin panel or API to get the user ID, organisation ID, and user secret for automation/integration.

4. **Backup the Populated Database**

```sh
docker exec -it ldap_sync_vaultwarden /vaultwarden backup
```

or

```sh
# make sqlite3 backup comand to use real path to the ldap_sync_vaultwarden_data volume in the host (/lib/docker/volumes/ldap_sync_vaultwarden_data/_data)
cd /lib/docker/volumes/ldap_sync_vaultwarden_data/_data
sqlite3 db.sqlite3 ".backup './db-backup.sqlite3'"
```
- Copy `/lib/docker/volumes/ldap_sync_vaultwarden_data/_data/db-backup.sqlite3` (or /data/db_YYYYMMDD_HHMMSS.sqlite3 if you use /vaultwarden backup) to your host for building a pre-populated image.

5. **Build Pre-Populated VaultWarden Image**

- Create a Dockerfile based on the official VaultWarden image, copying your backup to `/data/db.sqlite3`.
- Push the resulting image to Docker Hub (example: `vaultwarden-dev-populated`).

---

## Reproducibility
- You can always re-run these steps to create a fresh, pre-populated VaultWarden instance for testing or CI/CD.
- For automation, consider scripting user/org creation and backup steps.

---

## Notes
- All containers/services for the demo environment should use the `ldap_sync_` prefix for consistency.
- For VaultWarden version updates, repeat the provisioning and backup process, then rebuild and push the new image.
