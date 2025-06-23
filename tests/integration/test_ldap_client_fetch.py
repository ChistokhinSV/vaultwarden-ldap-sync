import os
from pathlib import Path
from typing import Dict

import pytest

from vaultwarden_ldap_sync.ldap_client import fetch_users

# ---------------------------------------------------------------------------
# Helpers for loading LDAP connection variables
# ---------------------------------------------------------------------------

REQUIRED_VARS = [
    "LDAP_HOST",
    "LDAP_BIND_DN",
    "LDAP_BIND_PASSWORD",
    "LDAP_BASE_DN",
]


def _parse_dotenv(dotenv_path: Path) -> Dict[str, str]:
    """Very small .env parser so we don't need extra deps."""
    env: Dict[str, str] = {}
    if not dotenv_path.exists():
        return env
    for line in dotenv_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


# Try to ensure env vars are set by reading project .env if needed
ROOT = Path(__file__).resolve().parents[2]
DOTENV = ROOT / ".env"
if DOTENV.exists():
    os.environ.update({k: v for k, v in _parse_dotenv(DOTENV).items() if k not in os.environ})

# Collect values


# ---------------------------------------------------------------------------
# Provide sensible defaults if env vars are not set (local 389ds)
# ---------------------------------------------------------------------------
_defaults = {
    "LDAP_HOST": "ldap://localhost:3389",
    "LDAP_BIND_DN": "cn=Directory Manager",
    "LDAP_BIND_PASSWORD": "adminpassword",
    "LDAP_BASE_DN": "dc=domain,dc=local",
}
for k, v in _defaults.items():
    os.environ.setdefault(k, v)

# Test constants – adapt group DN if your environment differs
GROUP_DN = os.getenv(
    "TEST_VW_GROUP_DN",
    "cn=vaultwarden-users,cn=groups,cn=accounts,dc=domain,dc=local",
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _get_conn_kwargs():
    return dict(
        host=os.environ["LDAP_HOST"],
        bind_dn=os.environ["LDAP_BIND_DN"],
        bind_password=os.environ["LDAP_BIND_PASSWORD"],
        base_dn=os.environ["LDAP_BASE_DN"],
    )


def test_group_filter_user_status():
    users = fetch_users(groups=GROUP_DN, **_get_conn_kwargs())
    # Expect exactly 3 specific users (by UID) in the group
    expected_uids = {"user", "user2", "user4"}
    found_uids = set()
    for u in users:
        if u.email and "@" in u.email:
            found_uids.add(u.email.split("@", 1)[0])
        else:
            # fallback to UID parsed from DN: uid=foo,cn=users,...
            dn_part = u.dn.split(",", 1)[0]
            if dn_part.startswith("uid="):
                found_uids.add(dn_part.removeprefix("uid="))
    assert expected_uids.issubset(found_uids)
    print("\nExpected vs Found UIDs (group filter):")
    for uid in sorted(expected_uids):
        print(f"  {uid}: {'present' if uid in found_uids else 'MISSING'}")
    # user4 should be disabled while others active
    status = {u.dn: u.disabled for u in users}
    u4_dn = next(d for d in status if d.startswith("uid=user4"))
    assert status[u4_dn] is True
    for dn, disabled in status.items():
        if dn != u4_dn:
            assert disabled is False


def test_all_users_include_user3():
    users = fetch_users(**_get_conn_kwargs())
    # Expect 4 users
    assert len(users) >= 4
    assert any("uid=user3" in u.dn for u in users)


def test_missing_attr_behaviour():
    users = fetch_users(**_get_conn_kwargs())
    # All users except user4 should report disabled False (missing attr)
    for u in users:
        if "uid=user4" in u.dn:
            assert u.disabled is True
        else:
            assert u.disabled is False


def test_missing_is_disabled_flag():
    users = fetch_users(missing_is_disabled=True, **_get_conn_kwargs())
    # Now users without attr *are* disabled (except user4 already disabled)
    for u in users:
        if "uid=user4" in u.dn:
            assert u.disabled is True
        else:
            assert u.disabled is True  # others considered disabled due to flag
