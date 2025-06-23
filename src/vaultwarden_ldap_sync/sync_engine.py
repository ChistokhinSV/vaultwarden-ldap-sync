"""Main synchronisation engine – drives LDAP ↔ VaultWarden reconciliation.

This module is intentionally *pure* (no direct I/O except logging) so that it
is easy to unit-test by providing stubbed fetchers / clients.
"""
from __future__ import annotations

import logging
from dataclasses import asdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Set

from .config import Config
from .ldap_client import LdapUser, fetch_users
from .vw_client import OrgUser, VaultWardenClient

logger = logging.getLogger("vaultwarden_ldap_sync.engine")

# ---------------------------------------------------------------------------
# Dataclasses for result reporting
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SyncActions:
    """Calculated actions for a reconciliation cycle."""

    invite: Set[str] = field(default_factory=set)
    revoke: Set[str] = field(default_factory=set)
    restore: Set[str] = field(default_factory=set)

    def any(self) -> bool:
        return bool(self.invite or self.revoke or self.restore)


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------


def _calculate_actions(
    *,
    ldap_users: List[LdapUser],
    vw_users: Dict[str, OrgUser],
    whitelist: Set[str],
    ldap_users_only: bool,
) -> SyncActions:
    """Return which e-mail addresses need to be invited/revoked/restored."""

    ldap_enabled = {u.email.lower() for u in ldap_users if u.email and not u.disabled}
    ldap_disabled = {u.email.lower() for u in ldap_users if u.email and u.disabled}

    vw_active = {e for e, u in vw_users.items() if u.active}
    vw_revoked = {e for e, u in vw_users.items() if u.revoked}

    actions = SyncActions()

    # invites: enabled in LDAP but no presence in VW at all
    actions.invite = ldap_enabled - vw_active - vw_revoked - whitelist

    # revoke: disabled in LDAP but currently active in VW
    actions.revoke = (ldap_disabled & vw_active) - whitelist

    # restore: enabled in LDAP but currently *revoked* in VW
    actions.restore = ldap_enabled & vw_revoked

    if ldap_users_only:
        # revoke everyone active but not in ldap_enabled, taking whitelist into account
        extra = (vw_active - ldap_enabled) - whitelist
        actions.revoke |= extra

    return actions


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_sync(
    cfg: Config,
    *,
    fetcher: Callable[[Config], List[LdapUser]] | None = None,
    vw_factory: Callable[[Config], VaultWardenClient] | None = None,
) -> SyncActions:
    """Execute a full reconciliation cycle and perform required VW actions.

    The *fetcher* and *vw_factory* are injectable for unit-tests; if ``None``
    the real implementations are used.
    """
    # --------------------------------------------------------------
    # Log configuration, masking sensitive values
    # --------------------------------------------------------------
    cfg_dict = asdict(cfg)
    for k in cfg_dict:
        if any(s in k.lower() for s in ("password", "secret")):
            cfg_dict[k] = "***"
    logger.debug("Starting sync run with config: %s", cfg_dict)

    # ------------------------------------------------------------------
    # 1. Gather state
    # ------------------------------------------------------------------
    ldap_fetch = fetcher or (
        lambda c: fetch_users(
            host=c.ldap_host,
            bind_dn=c.ldap_bind_dn,
            bind_password=c.ldap_bind_password,
            base_dn=c.ldap_base_dn,
            object_type=c.ldap_object_type,
            groups=c.ldap_user_groups,
            additional_filter=c.ldap_filter,
            group_attr=c.ldap_group_attr,
            email_attr=c.ldap_mail_attr,
            disabled_attr=c.ldap_disabled_attr,
            disabled_values=c.ldap_disabled_values,
            missing_is_disabled=c.ldap_missing_is_disabled,
            ignore_cert=c.ignore_ldaps_cert,
            ca_file=c.ldap_ca_file,
        )
    )

    ldap_users = ldap_fetch(cfg)
    logger.debug("Fetched %d LDAP entries", len(ldap_users))
    for u in ldap_users:
        logger.debug("LDAP: %s – %s – %s", getattr(u, 'dn', 'no-dn'), u.email, "disabled" if u.disabled else "enabled")

    vw_client = vw_factory(cfg) if vw_factory else VaultWardenClient(
        url=cfg.vw_url,
        client_id=cfg.vw_client_id,
        client_secret=cfg.vw_client_secret,
        org_id=cfg.vw_org_id,
        ignore_cert=cfg.ignore_vw_cert,
    )

    vw_users_map = vw_client.user_map()
    logger.debug("Fetched %d VW org users", len(vw_users_map))
    for email, user in vw_users_map.items():
        logger.debug("VW: %s – %s", email, "revoked" if user.revoked else ("active" if user.active else "inactive"))

    # ------------------------------------------------------------------
    # 2. Calculate actions
    # ------------------------------------------------------------------
    own_email: str | None = None
    if cfg.prevent_self_lock:
        client_uuid = cfg.vw_client_id.removeprefix("user.")
        own_email = vw_client.our_email(client_uuid)
        if own_email:
            own_email = own_email.lower()
            logger.debug("Whitelisting self e-mail %s to avoid self-lock", own_email)

    whitelist = {own_email} if own_email else set()

    actions = _calculate_actions(
        ldap_users=ldap_users,
        vw_users=vw_users_map,
        whitelist=whitelist,
        ldap_users_only=cfg.ldap_users_only,
    )

    logger.debug("Action plan – invite: %s, revoke: %s, restore: %s", actions.invite, actions.revoke, actions.restore)

    # ------------------------------------------------------------------
    # 3. Perform actions (INFO level)
    # ------------------------------------------------------------------
    errors: List[str] = []
    for email in sorted(actions.invite):
        logger.info("Inviting user %s", email)
        try:
            vw_client.invite(email)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to invite %s: %s", email, exc)
            errors.append(f"invite {email}: {exc}")

    for email in sorted(actions.revoke):
        logger.info("Revoking user %s", email)
        try:
            vw_client.revoke(vw_users_map[email].id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to revoke %s: %s", email, exc)
            errors.append(f"revoke {email}: {exc}")

    for email in sorted(actions.restore):
        logger.info("Restoring user %s", email)
        try:
            vw_client.restore(vw_users_map[email].id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to restore %s: %s", email, exc)
            errors.append(f"restore {email}: {exc}")

    if errors:
        logger.warning("Errors encountered during sync: %s", "; ".join(errors))
        raise RuntimeError("; ".join(errors))

    return actions
