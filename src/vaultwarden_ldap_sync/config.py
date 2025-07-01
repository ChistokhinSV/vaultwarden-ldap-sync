"""Central configuration dataclass loaded from environment variables.

Only parameters essential for the sync engine are included.  Anything used
*solely* during connectivity tests stays in :pyfile:`main.py` for now.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from .core.constants import (
    YES_VALUES,
    DEFAULT_LDAP_HOST,
    DEFAULT_VW_URL,
    DEFAULT_LDAP_GROUP_ATTR,
    DEFAULT_LDAP_MAIL_ATTR,
    DEFAULT_LDAP_DISABLED_ATTR,
    DEFAULT_LDAP_DISABLED_VALUES,
)


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
    ldap_host: str = os.getenv('LDAP_HOST', DEFAULT_LDAP_HOST)
    ldap_bind_dn: str = os.getenv('LDAP_BIND_DN', '')
    ldap_bind_password: str = os.getenv('LDAP_BIND_PASSWORD', '')
    ldap_base_dn: str = os.getenv('LDAP_BASE_DN', '')

    ldap_object_type: str | None = os.getenv('LDAP_OBJECT_TYPE', None)
    ldap_user_groups: str | None = os.getenv('LDAP_USER_GROUPS', None)
    ldap_group_attr: str = os.getenv('LDAP_GROUP_ATTRIBUTE', DEFAULT_LDAP_GROUP_ATTR)
    ldap_filter: str | None = os.getenv('LDAP_FILTER', None)
    ldap_mail_attr: str = os.getenv('LDAP_MAIL_FIELD', DEFAULT_LDAP_MAIL_ATTR)
    ldap_disabled_attr: str | None = os.getenv('LDAP_DISABLED_ATTRIBUTE', DEFAULT_LDAP_DISABLED_ATTR)
    ldap_disabled_values: List[str] = field(default_factory=lambda: _env_list('LDAP_DISABLED_VALUES') or DEFAULT_LDAP_DISABLED_VALUES)
    ldap_missing_is_disabled: bool = _env_bool('LDAP_MISSING_IS_DISABLED', False)
    ldap_users_only: bool = _env_bool('LDAP_USERS_ONLY', False)

    ignore_ldaps_cert: bool = _env_bool('IGNORE_LDAPS_CERT', False)
    ldap_ca_file: str | None = os.getenv('LDAP_CA_FILE', None)

    # VaultWarden -------------------------------------------------------
    vw_url: str = os.getenv('VW_URL', DEFAULT_VW_URL)
    vw_client_id: str = os.getenv('VW_USER_CLIENT_ID', '')
    vw_client_secret: str = os.getenv('VW_USER_CLIENT_SECRET', '')
    vw_org_id: str = os.getenv('VW_ORG_ID', '')
    ignore_vw_cert: bool = _env_bool('IGNORE_VW_CERT', False)

    # Misc --------------------------------------------------------------
    prevent_self_lock: bool = _env_bool('PREVENT_SELF_LOCK', True)

    debug: str = os.getenv('DEBUG', '').upper()

    def __post_init__(self) -> None:
        # strip prefixes from org id if present
        if self.vw_org_id.startswith('organization.'):
            self.vw_org_id = self.vw_org_id.split('.')[1]

    @classmethod
    def parse_multi_org_config(cls):
        """Parse multi-organization configuration from environment variables.
        
        Looks for environment variables with suffixed patterns:
        - VW_USER_CLIENT_ID_<ORG_NAME>
        - VW_USER_CLIENT_SECRET_<ORG_NAME>  
        - VW_ORG_ID_<ORG_NAME>
        - LDAP_USER_GROUPS_<ORG_NAME> (optional)
        
        Returns:
            Dict[str, Dict[str, str]]: Organization name -> config dict
            
        Example:
            {
                'VAULTWARDEN': {
                    'vw_client_id': 'user.810e12f0-...',
                    'vw_client_secret': 'fxBn9nB4neag2HD6...',
                    'vw_org_id': '2822e5d3-3a77-...',
                    'ldap_user_groups': 'cn=vaultwarden-users,...'
                },
                'TESTING': { ... }
            }
        """
        import os
        
        # Find all environment variables with the expected patterns
        multi_org_vars = {}
        
        for env_var, value in os.environ.items():
            # Parse VW_USER_CLIENT_ID_<ORG_NAME>
            if env_var.startswith('VW_USER_CLIENT_ID_'):
                org_name = env_var[len('VW_USER_CLIENT_ID_'):]
                if org_name not in multi_org_vars:
                    multi_org_vars[org_name] = {}
                multi_org_vars[org_name]['vw_client_id'] = value
                
            # Parse VW_USER_CLIENT_SECRET_<ORG_NAME>
            elif env_var.startswith('VW_USER_CLIENT_SECRET_'):
                org_name = env_var[len('VW_USER_CLIENT_SECRET_'):]
                if org_name not in multi_org_vars:
                    multi_org_vars[org_name] = {}
                multi_org_vars[org_name]['vw_client_secret'] = value
                
            # Parse VW_ORG_ID_<ORG_NAME>
            elif env_var.startswith('VW_ORG_ID_'):
                org_name = env_var[len('VW_ORG_ID_'):]
                if org_name not in multi_org_vars:
                    multi_org_vars[org_name] = {}
                multi_org_vars[org_name]['vw_org_id'] = value
                
            # Parse LDAP_USER_GROUPS_<ORG_NAME> (optional)
            elif env_var.startswith('LDAP_USER_GROUPS_'):
                org_name = env_var[len('LDAP_USER_GROUPS_'):]
                if org_name not in multi_org_vars:
                    multi_org_vars[org_name] = {}
                multi_org_vars[org_name]['ldap_user_groups'] = value
        
        # Filter to only include organizations with required VaultWarden credentials
        complete_orgs = {}
        for org_name, org_config in multi_org_vars.items():
            required_keys = ['vw_client_id', 'vw_client_secret', 'vw_org_id']
            if all(key in org_config for key in required_keys):
                complete_orgs[org_name] = org_config
        
        return complete_orgs
