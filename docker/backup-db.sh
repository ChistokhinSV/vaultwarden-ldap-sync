#!/bin/bash
sqlite3 /var/lib/docker/volumes/ldap_sync_vaultwarden_data/_data/db.sqlite3 ".backup './data/db-backup.sqlite3'"
