#!/bin/bash
sqlite3 /var/lib/docker/volumes/org_invite_vaultwarden_data/_data/db.sqlite3 ".backup './data/db-backup.sqlite3'"
