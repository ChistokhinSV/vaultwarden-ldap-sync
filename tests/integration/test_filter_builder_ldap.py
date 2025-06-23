import os
from pathlib import Path
from typing import Dict, List

import pytest
from ldap3 import Server, Connection, ALL


from vaultwarden_ldap_sync.filter_builder import build_ldap_filter

# ---------------------------------------------------------------------------
# Helper to load .env so tests run even when executed outside docker compose
# ---------------------------------------------------------------------------
REQUIRED_VARS = ["LDAP_HOST", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_BASE_DN"]


def _parse_dotenv(dotenv_path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if dotenv_path.exists():
        for line in dotenv_path.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


ROOT = Path(__file__).resolve().parents[2]
DOTENV = ROOT / ".env"
if DOTENV.exists():
    os.environ.update({k: v for k, v in _parse_dotenv(DOTENV).items() if k not in os.environ})

LDAP_HOST = os.getenv("LDAP_HOST")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")


# VaultWarden users group DN (single or comma-sep list)
GROUP_DNS = os.getenv(
    "TEST_VW_GROUP_DNS",
    "cn=vaultwarden-users,cn=groups,cn=accounts,dc=domain,dc=local",
)


# ---------------------------------------------------------------------------
# Provide sensible defaults if variables are still undefined (assume local 389ds)
# ---------------------------------------------------------------------------
_defaults = {
    "LDAP_HOST": "ldap://localhost:3389",
    "LDAP_BIND_DN": "cn=Directory Manager",
    "LDAP_BIND_PASSWORD": "adminpassword",
    "LDAP_BASE_DN": "dc=domain,dc=local",
}
for k, v in _defaults.items():
    os.environ.setdefault(k, v)

LDAP_HOST = os.environ["LDAP_HOST"]
LDAP_BIND_DN = os.environ["LDAP_BIND_DN"]
LDAP_BIND_PASSWORD = os.environ["LDAP_BIND_PASSWORD"]
LDAP_BASE_DN = os.environ["LDAP_BASE_DN"]


def _connect() -> Connection:
    server = Server(LDAP_HOST.replace("ldap://", ""), use_ssl=LDAP_HOST.lower().startswith("ldaps://"), get_info=ALL)
    conn = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)
    return conn


def test_object_class_person():
    conn = _connect()
    flt = build_ldap_filter(object_type="person")
    assert flt == "(objectClass=person)"
    assert conn.search(search_base=LDAP_BASE_DN, search_filter=flt, attributes=[])
    assert len(conn.entries) > 0  # expect at least one person entry in test DIT
    conn.unbind()


def test_group_filter():
    conn = _connect()
    flt = build_ldap_filter(groups=GROUP_DNS)
    conn.search(search_base=LDAP_BASE_DN, search_filter=flt, attributes=["memberOf"])
    rows = []
    expected_set = {GROUP_DNS}
    for entry in conn.entries:
        member_of = set(entry.memberOf.values) if "memberOf" in entry else set()
        matched = GROUP_DNS in member_of
        rows.append((str(entry.entry_dn), list(member_of), matched))
    print("\nLDAP group filter results:")
    for dn, groups, ok in rows:
        print(f"  {dn}: contains '{GROUP_DNS}'? {ok}; memberOf={groups}")
    # ensure all entries matched
    assert all(ok for *_ , ok in rows)
    conn.unbind()
