"""LDAP client utilities for fetching users with group membership and lockout state.

The implementation is intentionally simple and built on *ldap3* so it can work
with multiple directory flavours (389ds/FreeIPA, OpenLDAP, Active Directory…)
without extra dependencies.

Features
~~~~~~~~
* Connects using simple bind (service account DN/password).
* Supports `ldaps://` with optional certificate ignore or CA file (via calling
  :pyfunc:`vaultwarden_ldap_sync.main.build_ldap_server` but without import
  cycle).
* Builds filters using :pyfunc:`vaultwarden_ldap_sync.filter_builder.build_ldap_filter`.
* Extracts:

  - Distinguished Name (DN)
  - Email (configurable attribute, default ``mail``)
  - Group list (attribute name configurable, default ``memberOf``)
  - Disabled flag determined by *disabled attribute* (configurable, default
    ``nsAccountLock``) and *disabled values* (configurable list, default
    ["TRUE", "true", "1", "yes", "YES"]).  If the attribute is missing **the
    account is considered enabled** because many directory schemas omit the
    attribute by default.  This behaviour may be overridden passing
    ``missing_is_disabled=True``.

Return value is a list of :class:`LdapUser` dataclass instances.
"""
from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Iterable, List, Sequence
import logging

from ldap3 import ALL, Connection, Server, Tls

# local import without circular dependency
from .filter_builder import build_ldap_filter

logger = logging.getLogger("vaultwarden_ldap_sync.ldap")

__all__ = ["LdapUser", "fetch_users"]


@dataclass(slots=True)
class LdapUser:
    dn: str
    email: str | None
    groups: List[str]
    disabled: bool

    def __repr__(self) -> str:  # pragma: no cover – cosmetic
        return (
            "LdapUser(" f"dn={self.dn!r}, email={self.email!r}, groups={len(self.groups)} items, "
            f"disabled={self.disabled})"
        )


# Helper ---------------------------------------------------------------------


def _build_server(host: str, ignore_cert: bool = False, ca_file: str | None = None) -> Server:
    """Build an ldap3 :class:`Server` with correct TLS settings."""
    use_ssl = host.lower().startswith("ldaps://")
    clean_host = host.replace("ldap://", "").replace("ldaps://", "")

    tls: Tls | None = None
    if use_ssl:
        if ignore_cert:
            tls = Tls(validate=ssl.CERT_NONE)
        elif ca_file:
            tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file)
    return Server(clean_host, use_ssl=use_ssl, get_info=None, tls=tls)


# Public API -----------------------------------------------------------------


def fetch_users(
    *,
    host: str,
    bind_dn: str,
    bind_password: str,
    base_dn: str,
    object_type: str | None = "person",
    groups: str | None = None,
    additional_filter: str | None = None,
    group_attr: str = "memberOf",
    email_attr: str = "mail",
    disabled_attr: str | None = "nsAccountLock",
    disabled_values: Sequence[str] | None = ("TRUE", "true", "1", "yes", "YES"),
    missing_is_disabled: bool = False,
    ignore_cert: bool = False,
    ca_file: str | None = None,
    timeout: int | float = 5,
) -> List[LdapUser]:
    """Retrieve LDAP users.

    Parameters are mostly self-explanatory mirrors of environment variables.
    """
    server = _build_server(host, ignore_cert=ignore_cert, ca_file=ca_file)
    conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True, receive_timeout=timeout)

    search_filter = build_ldap_filter(object_type, groups, additional_filter, group_attr=group_attr)

    attributes = [email_attr, group_attr]
    if disabled_attr:
        attributes.append(disabled_attr)

    logger.debug(f"Fetching LDAP at {base_dn} with filter: {search_filter} and attributes: {attributes}")

    conn.search(search_base=base_dn, search_filter=search_filter, attributes=attributes)

    users: list[LdapUser] = []
    dl_vals = set(disabled_values or ())

    for entry in conn.entries:
        # DN
        dn = str(entry.entry_dn)

        # email (may be multi-valued – take first)
        email_val: str | None = None
        if email_attr in entry and entry[email_attr].value:
            val = entry[email_attr].value
            email_val = val[0] if isinstance(val, Iterable) and not isinstance(val, str) else str(val)

        # groups list
        groups_val: list[str] = []
        if group_attr in entry and entry[group_attr].value:
            raw = entry[group_attr].value
            if isinstance(raw, list):
                groups_val = [str(g) for g in raw]
            else:
                groups_val = [str(raw)]

        # disabled flag
        # Determine disabled flag
        disabled = False
        attr_present = disabled_attr and disabled_attr in entry
        if attr_present:
            raw_val = entry[disabled_attr].value
            # Treat empty/None as *missing* for the purpose of missing_is_disabled
            if raw_val in (None, "", [], ()):  # noqa: RUF100
                disabled = missing_is_disabled
            elif isinstance(raw_val, list):
                disabled = any(str(v) in dl_vals for v in raw_val)
            else:
                disabled = str(raw_val) in dl_vals
        else:
            disabled = missing_is_disabled

        users.append(LdapUser(dn=dn, email=email_val, groups=groups_val, disabled=disabled))

    conn.unbind()
    return users
