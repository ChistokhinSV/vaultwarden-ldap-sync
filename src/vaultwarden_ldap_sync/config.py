"""Central configuration dataclass loaded from environment variables.

Only parameters essential for the sync engine are included.  Anything used
*solely* during connectivity tests stays in :pyfile:`main.py` for now.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Sequence


YES_VALUES: Sequence[str] = ("1", "TRUE", "YES", "ON", "true", "yes", "on")


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val in YES_VALUES


def _env_list(name: str) -> List[str]:
    raw = os.getenv(name, "").strip()
    return [s for s in [p.strip() for p in raw.split(",")] if s]


@dataclass(slots=True)
class Config:
    """Runtime configuration derived from environment variables."""

    # LDAP --------------------------------------------------------------
    ldap_host: str = os.getenv("LDAP_HOST", "ldap://localhost:389")
    ldap_bind_dn: str = os.getenv("LDAP_BIND_DN", "")
    ldap_bind_password: str = os.getenv("LDAP_BIND_PASSWORD", "")
    ldap_base_dn: str = os.getenv("LDAP_BASE_DN", "")

    ldap_object_type: str | None = os.getenv("LDAP_OBJECT_TYPE", None)
    ldap_user_groups: str | None = os.getenv("LDAP_USER_GROUPS", None)
    ldap_group_attr: str = os.getenv("LDAP_GROUP_ATTRIBUTE", "memberOf")
    ldap_filter: str | None = os.getenv("LDAP_FILTER", None)
    ldap_mail_attr: str = os.getenv("LDAP_MAIL_FIELD", "mail")
    ldap_disabled_attr: str | None = os.getenv("LDAP_DISABLED_ATTRIBUTE", "nsAccountLock")
    ldap_disabled_values: List[str] = field(default_factory=lambda: _env_list("LDAP_DISABLED_VALUES") or [
        "TRUE",
        "true",
        "1",
        "yes",
        "YES",
    ])
    ldap_missing_is_disabled: bool = _env_bool("LDAP_MISSING_IS_DISABLED", False)
    ldap_users_only: bool = _env_bool("LDAP_USERS_ONLY", False)

    ignore_ldaps_cert: bool = _env_bool("IGNORE_LDAPS_CERT", False)
    ldap_ca_file: str | None = os.getenv("LDAP_CA_FILE", None)

    # VaultWarden -------------------------------------------------------
    vw_url: str = os.getenv("VW_URL", "http://localhost:8080")
    vw_client_id: str = os.getenv("VW_USER_CLIENT_ID", "")
    vw_client_secret: str = os.getenv("VW_USER_CLIENT_SECRET", "")
    vw_org_id: str = os.getenv("VW_ORG_ID", "")
    ignore_vw_cert: bool = _env_bool("IGNORE_VW_CERT", False)

    # Misc --------------------------------------------------------------
    prevent_self_lock: bool = _env_bool("PREVENT_SELF_LOCK", True)

    debug: str = os.getenv("DEBUG", "").upper()

    def __post_init__(self) -> None:
        # strip prefixes from org id if present
        if self.vw_org_id.startswith("organization."):
            self.vw_org_id = self.vw_org_id.split(".")[1]
